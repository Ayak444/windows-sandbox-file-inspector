[CmdletBinding()]
param([string]$SamplePath, [ValidateRange(10,300)][int]$DurationSeconds=60, [switch]$NoOpen)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $PSScriptRoot -ne 'C:\SandboxTools') { throw 'Run this tool only inside Windows Sandbox, never on the host.' }
. (Join-Path $PSScriptRoot 'File-Inspector.Core.ps1')
. (Join-Path $PSScriptRoot 'Behavior.Core.ps1')
$desktop=[Environment]::GetFolderPath('Desktop')
$samples=[IO.Path]::GetFullPath((Join-Path $desktop 'Samples'))
if (!$SamplePath) {
    Add-Type -AssemblyName System.Windows.Forms
    $picker=[Windows.Forms.OpenFileDialog]::new()
    $picker.InitialDirectory=$samples; $picker.Filter='Executable (*.exe)|*.exe'; $picker.Title='Select one EXE inside Samples to run and observe'
    if ($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { return }
    $SamplePath=$picker.FileName
    if ([Windows.Forms.MessageBox]::Show('Run this EXE inside the offline sandbox for 60 seconds? It may be malicious. Close the sandbox after reviewing the report.','Behavior analysis',[Windows.Forms.MessageBoxButtons]::YesNo) -ne [Windows.Forms.DialogResult]::Yes) { return }
}
$SamplePath=[IO.Path]::GetFullPath($SamplePath)
if (!$SamplePath.StartsWith($samples+'\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($SamplePath) -ne '.exe') { throw 'Select an EXE inside the isolated desktop Samples folder.' }
$cursor=$SamplePath
while ($cursor.Length -ge $samples.Length) {
    $entry=Get-Item -LiteralPath $cursor -Force
    if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Links/junctions are not accepted.' }
    if ($cursor -eq $samples) { break }; $cursor=[IO.Path]::GetDirectoryName($cursor)
}
# Keep the original isolation policy; refuse execution if a default route was added.
if (@(Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') }).Count -gt 0) { throw 'Network route found. Recreate the offline sandbox before observing samples.' }
$output=Join-Path $desktop ('Analysis\Behavior-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[Guid]::NewGuid().ToString('N').Substring(0,6))
New-Item -ItemType Directory -Path $output -Force | Out-Null
$errors=[Collections.Generic.List[string]]::new()
$nodes=[Collections.Generic.List[object]]::new(); $timeline=[Collections.Generic.List[object]]::new()
$files=[Collections.Generic.List[object]]::new(); $connections=[Collections.Generic.List[object]]::new()
$active=@{}; $networkSeen=@{}; $subscribers=[Collections.Generic.List[string]]::new(); $watchers=[Collections.Generic.List[object]]::new()
$nonce='Behavior-'+[Guid]::NewGuid().ToString('N'); $traceAvailable=$false; $watchAvailable=$false; $polls=0; $completed=$false
function Record-BehaviorError([string]$Message) { if (!$errors.Contains($Message) -and $errors.Count -lt 100) { $errors.Add($Message) } }
function Record-BehaviorEvent([string]$Kind,[string]$Detail,[string]$At=(Get-Date).ToUniversalTime().ToString('o')) {
    if ($timeline.Count -lt 10000) { $timeline.Add([pscustomobject]@{At=$At;Kind=$Kind;Detail=$Detail}) }
    else { Record-BehaviorError 'Timeline limit reached; events omitted.' }
}
function Register-BehaviorProcess([int]$ProcessNumber,[int]$ParentNumber,[string]$Name,[string]$Path,[string]$Command,[datetime]$Created,[string]$Source,[switch]$Root) {
    $number=[string]$ProcessNumber
    if ($active.ContainsKey($number)) {
        $existing=$active[$number]
        if ([Math]::Abs(($Created.ToUniversalTime()-[datetime]::Parse($existing.CreatedAt).ToUniversalTime()).TotalSeconds) -lt 1) {
            if ($Path) { $existing.Path=$Path }; if ($Command) { $existing.CommandLine=$Command }
            return
        }
    }
    $parentKey=''
    if (!$Root) {
        if (!$active.ContainsKey([string]$ParentNumber)) { return }
        $parent=$active[[string]$ParentNumber]
        if ([datetime]::Parse($parent.CreatedAt).ToUniversalTime() -gt $Created.ToUniversalTime()) { return }
        $parentKey=$parent.Key
    }
    if ($nodes.Count -ge 512) { Record-BehaviorError 'Process node limit reached.'; return }
    $utc=$Created.ToUniversalTime()
    $node=[pscustomobject]@{Key=$number+':'+$utc.Ticks;ProcessId=$ProcessNumber;ParentId=$ParentNumber;ParentKey=$parentKey;Name=$Name;Path=$Path;CommandLine=$Command;CreatedAt=$utc.ToString('o');FirstSeen=(Get-Date).ToUniversalTime().ToString('o');EndedAt='';Source=$Source}
    $nodes.Add($node); $active[$number]=$node
    Record-BehaviorEvent 'ProcessStart' ($node.Key+' '+$Name+' parent='+$parentKey+' '+$Command) $utc.ToString('o')
}
$started=(Get-Date).ToUniversalTime(); $ended=$started
$before=@(); $after=@()
try {
    $static=Get-FileInspection (Get-Item -LiteralPath $SamplePath) $samples
    $defender=Get-DefenderScan -Path $SamplePath -OutputDirectory $output
    try { $before=@(Get-BehaviorPersistence) } catch { Record-BehaviorError ('Persistence baseline unavailable: '+$_.Exception.Message) }
    try {
        Add-Type -AssemblyName System.Management
        foreach ($kind in @('Start','Stop')) {
            $watcher=[Management.ManagementEventWatcher]::new('SELECT * FROM Win32_Process'+$kind+'Trace')
            $source=$nonce+'-Process'+$kind
            [void](Register-ObjectEvent -InputObject $watcher -EventName EventArrived -SourceIdentifier $source)
            $subscribers.Add($source); $watchers.Add($watcher); $watcher.Start()
        }
        $traceAvailable=$true
    } catch { Record-BehaviorError ('Process event sensor unavailable; polling fallback: '+$_.Exception.Message) }
    $fileWatcherCount=0
    foreach ($folder in @($samples,[Environment]::GetFolderPath('ApplicationData'),[IO.Path]::GetFullPath($env:TEMP))) {
        try {
            $watcher=[IO.FileSystemWatcher]::new($folder); $watcher.IncludeSubdirectories=$true; $watcher.InternalBufferSize=32768
            foreach ($kind in @('Created','Changed','Deleted','Renamed','Error')) {
                $source=$nonce+'-File'+$fileWatcherCount+'-'+$kind
                [void](Register-ObjectEvent -InputObject $watcher -EventName $kind -SourceIdentifier $source)
                $subscribers.Add($source)
            }
            $watchers.Add($watcher); $watcher.EnableRaisingEvents=$true; $fileWatcherCount++
        } catch { Record-BehaviorError ('File sensor unavailable: '+$folder+' '+$_.Exception.Message) }
    }
    $watchAvailable=$fileWatcherCount -eq 3
    $started=(Get-Date).ToUniversalTime()
    Record-BehaviorEvent 'ObservationStart' $SamplePath
    $launched=Start-Process -FilePath $SamplePath -WorkingDirectory ([IO.Path]::GetDirectoryName($SamplePath)) -PassThru
    $rootInfo=Get-CimInstance Win32_Process -Filter ('ProcessId='+$launched.Id) -ErrorAction SilentlyContinue
    $rootCreated=$started; $rootCommand=$SamplePath
    if ($null -ne $rootInfo) { $rootCreated=$rootInfo.CreationDate; $rootCommand=[string]$rootInfo.CommandLine }
    Register-BehaviorProcess $launched.Id 0 ([IO.Path]::GetFileName($SamplePath)) $SamplePath $rootCommand $rootCreated 'LaunchHandle' -Root
    $deadline=$started.AddSeconds($DurationSeconds)
    do {
        Start-Sleep -Milliseconds 700
        foreach ($eventRow in @(Get-Event | Where-Object { $_.SourceIdentifier.StartsWith($nonce) })) {
            try {
                if ($eventRow.SourceIdentifier -like '*-Process*') {
                    $trace=$eventRow.SourceEventArgs.NewEvent
                    $number=[string]$trace.ProcessID; $at=[datetime]::FromFileTimeUtc([long]$trace.TIME_CREATED)
                    if ($eventRow.SourceIdentifier -like '*ProcessStart') {
                        $details=Get-CimInstance Win32_Process -Filter ('ProcessId='+$trace.ProcessID) -ErrorAction SilentlyContinue
                        $path=''; $command=''
                        if ($null -ne $details -and [Math]::Abs(($details.CreationDate.ToUniversalTime()-$at).TotalSeconds) -lt 1) { $path=[string]$details.ExecutablePath; $command=[string]$details.CommandLine; $at=$details.CreationDate }
                        Register-BehaviorProcess ([int]$trace.ProcessID) ([int]$trace.ParentProcessID) ([string]$trace.ProcessName) $path $command $at 'ProcessTrace'
                    } elseif ($active.ContainsKey($number) -and $at -ge [datetime]::Parse($active[$number].CreatedAt).ToUniversalTime()) {
                        $node=$active[$number]; $node.EndedAt=$at.ToString('o')
                        Record-BehaviorEvent ProcessStop ($node.Key+' '+$node.Name) $at.ToString('o'); $active.Remove($number)
                    }
                } elseif ($eventRow.SourceIdentifier.EndsWith('-Error')) { Record-BehaviorError 'FileSystemWatcher overflow/error; file events may be missing.' }
                else {
                    $detail=$eventRow.SourceEventArgs
                    if ($files.Count -lt 5000) {
                        $row=[pscustomobject]@{At=$eventRow.TimeGenerated.ToUniversalTime().ToString('o');Kind=[string]$detail.ChangeType;Path=[string]$detail.FullPath;Attribution='Time-correlated, process unknown'}
                        $files.Add($row); Record-BehaviorEvent ('File'+$row.Kind) ($row.Path+' [unattributed]') $row.At
                    } else { Record-BehaviorError 'File event limit reached; events omitted.' }
                }
            } catch { Record-BehaviorError ('Event collection failed: '+$_.Exception.Message) }
            finally { Remove-Event -EventIdentifier $eventRow.EventIdentifier -ErrorAction SilentlyContinue }
        }
        try {
            $snapshot=@(Get-CimInstance Win32_Process -ErrorAction Stop); $polls++
            for ($pass=0;$pass -lt 3;$pass++) {
                foreach ($process in $snapshot) {
                    if ($active.ContainsKey([string]$process.ProcessId) -or $active.ContainsKey([string]$process.ParentProcessId)) {
                        Register-BehaviorProcess ([int]$process.ProcessId) ([int]$process.ParentProcessId) ([string]$process.Name) ([string]$process.ExecutablePath) ([string]$process.CommandLine) $process.CreationDate 'CIM poll'
                    }
                }
            }
            $current=@{}
            foreach ($process in $snapshot) { $current[[string]$process.ProcessId]=$process }
            foreach ($number in @($active.Keys)) {
                if (!$current.ContainsKey($number) -or [Math]::Abs(($current[$number].CreationDate.ToUniversalTime()-[datetime]::Parse($active[$number].CreatedAt).ToUniversalTime()).TotalSeconds) -ge 1) {
                    $node=$active[$number]; $node.EndedAt=(Get-Date).ToUniversalTime().ToString('o')
                    Record-BehaviorEvent 'ProcessAbsentAtPoll' $node.Key; $active.Remove($number)
                }
            }
        } catch { Record-BehaviorError ('Process poll failed: '+$_.Exception.Message) }
        try {
            foreach ($tcp in Get-NetTCPConnection -ErrorAction Stop) {
                $number=[string]$tcp.OwningProcess
                if (!$active.ContainsKey($number)) { continue }
                $node=$active[$number]; $key=$node.Key+'|'+$tcp.LocalAddress+':'+$tcp.LocalPort+'|'+$tcp.RemoteAddress+':'+$tcp.RemotePort+'|'+$tcp.State
                if (!$networkSeen.ContainsKey($key) -and $connections.Count -lt 1000) {
                    $networkSeen[$key]=$true
                    $row=[pscustomobject]@{At=(Get-Date).ToUniversalTime().ToString('o');ProcessKey=$node.Key;RemoteAddress=[string]$tcp.RemoteAddress;RemotePort=$tcp.RemotePort;LocalAddress=[string]$tcp.LocalAddress;LocalPort=$tcp.LocalPort;State=[string]$tcp.State}
                    $connections.Add($row); Record-BehaviorEvent 'TCP' $key $row.At
                }
            }
            if ($connections.Count -ge 1000) { Record-BehaviorError 'TCP event limit reached.' }
        } catch { Record-BehaviorError ('TCP sensor unavailable: '+$_.Exception.Message) }
        $elapsed=((Get-Date).ToUniversalTime()-$started).TotalSeconds
        Write-Progress -Activity 'Offline behavior observation (interact with the sample window)' -Status ([string][Math]::Round($elapsed)+' / '+$DurationSeconds+' seconds') -PercentComplete ([Math]::Min(100,100*$elapsed/$DurationSeconds))
    } while ((Get-Date).ToUniversalTime() -lt $deadline)
    $completed=$true
} catch { Record-BehaviorError ('Observation failed: '+$_.Exception.Message) }
finally {
    $ended=(Get-Date).ToUniversalTime()
    foreach ($source in $subscribers) { Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue }
    foreach ($watcher in $watchers) {
        try { if ($watcher -is [Management.ManagementEventWatcher]) { $watcher.Stop() }; $watcher.Dispose() } catch { }
    }
    foreach ($eventRow in @(Get-Event | Where-Object { $_.SourceIdentifier.StartsWith($nonce) })) { Remove-Event -EventIdentifier $eventRow.EventIdentifier -ErrorAction SilentlyContinue }
    Write-Progress -Activity 'Offline behavior observation (interact with the sample window)' -Completed
}
try { $after=@(Get-BehaviorPersistence) } catch { Record-BehaviorError ('Persistence final snapshot unavailable: '+$_.Exception.Message) }
if (!(Get-Variable static -ErrorAction SilentlyContinue)) { throw 'Static inspection never completed; see sandbox console.' }
$data=[pscustomobject]@{SamplePath=$SamplePath;StartedAt=$started.ToString('o');EndedAt=$ended.ToString('o');ActualDurationSeconds=($ended-$started).TotalSeconds;RequestedDurationSeconds=$DurationSeconds;Completed=$completed;ProcessPolls=$polls;ProcessTraceAvailable=$traceAvailable;FileWatchAvailable=$watchAvailable;Static=$static;Defender=$defender;Processes=@($nodes.ToArray());Timeline=@($timeline.ToArray());FileEvents=@($files.ToArray());Connections=@($connections.ToArray());PersistenceChanges=@(Compare-BehaviorPersistence $before $after);Errors=@($errors.ToArray());Assessment=$null}
$rules=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'behavior-rules.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$data.Assessment=Get-BehaviorAssessment $data $rules
$data | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $output 'behavior.json') -Encoding UTF8
ConvertTo-BehaviorHtml $data | Set-Content -LiteralPath (Join-Path $output 'behavior.html') -Encoding UTF8
(Join-Path $output 'behavior.html') | Set-Content -LiteralPath (Join-Path $desktop 'Analysis\Latest-Behavior-Report.txt') -Encoding UTF8
Write-Host ('Report: '+(Join-Path $output 'behavior.html'))
Write-Host 'Observation finished. The sample may still be running; close the Sandbox after reviewing results.'
if (!$NoOpen) { try { Start-Process -FilePath (Join-Path $output 'behavior.html') } catch { Write-Warning 'Open behavior.html manually inside the Sandbox.' } }
if (!$completed) { exit 1 }

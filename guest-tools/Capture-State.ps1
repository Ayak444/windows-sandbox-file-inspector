param([ValidateSet('before', 'after')][string]$Label = 'after')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $PSScriptRoot -ne 'C:\SandboxTools') {
    throw 'Run this script only inside Windows Sandbox, never on the host.'
}
$analysis = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Analysis'
New-Item -ItemType Directory -Path $analysis -Force | Out-Null
$captureErrors = [Collections.Generic.List[string]]::new()
function Read-Section([scriptblock]$Action) {
    try { & $Action } catch { $captureErrors.Add($_.Exception.Message) }
}
$runPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$state = [ordered]@{
    CapturedAt = (Get-Date).ToString('o')
    Processes = @(Read-Section { Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine })
    Services = @(Read-Section { Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, PathName })
    ScheduledTasks = @(Read-Section { Get-ScheduledTask | Select-Object TaskPath, TaskName, State, @{Name='Actions';Expression={ $_.Actions | Select-Object Execute, Arguments }} })
    TcpConnections = @(Read-Section { Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess })
    Autoruns = @(Read-Section {
        foreach ($path in $runPaths) {
            if (Test-Path -LiteralPath $path) {
                $properties = (Get-ItemProperty -LiteralPath $path).PSObject.Properties
                foreach ($property in $properties) {
                    if ($property.Name -notlike 'PS*') {
                        [pscustomobject]@{ Key = $path; Name = $property.Name; Value = $property.Value }
                    }
                }
            }
        }
    })
    StartupFiles = @(Read-Section {
        foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
            Get-ChildItem -LiteralPath $folder -File -Force | Select-Object FullName, Length, LastWriteTimeUtc
        }
    })
    CaptureErrors = @($captureErrors.ToArray())
}
$path = Join-Path $analysis ($Label + '.json')
$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
if ($Label -eq 'after') {
    $beforePath = Join-Path $analysis 'before.json'
    if (Test-Path -LiteralPath $beforePath) {
        $before = Get-Content -LiteralPath $beforePath -Raw | ConvertFrom-Json
        $summary = [Collections.Generic.List[string]]::new()
        $summary.Add('Snapshot differences; changes alone do not prove malware. Short-lived activity can be missed.')
        foreach ($section in @('Processes', 'Services', 'ScheduledTasks', 'TcpConnections', 'Autoruns', 'StartupFiles')) {
            $summary.Add("`r`n[$section]  <= before only; => after only")
            $old = @($before.$section | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 8 -Compress })
            $new = @($state[$section] | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 8 -Compress })
            $difference = @(Compare-Object -ReferenceObject $old -DifferenceObject $new)
            if ($difference.Count -eq 0) { $summary.Add('(no differences)') }
            foreach ($row in $difference) { $summary.Add($row.SideIndicator + ' ' + $row.InputObject) }
        }
        $summary.Add("`r`nCapture errors: review CaptureErrors in both JSON files.")
        $summary | Set-Content -LiteralPath (Join-Path $analysis 'changes.txt') -Encoding UTF8
    }
}
Write-Host "Saved inside the sandbox: $path"
if ($captureErrors.Count -gt 0) { Write-Warning 'Some sections could not be captured; inspect CaptureErrors.' }

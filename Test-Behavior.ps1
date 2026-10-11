Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'guest-tools\Behavior.Core.ps1')
$rules=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'guest-tools\behavior-rules.json') -Raw -Encoding UTF8 | ConvertFrom-Json
function Assert-Behavior($Condition,[string]$Message) { if (!$Condition) { throw "FAIL: $Message" }; Write-Host "PASS: $Message" }
foreach ($relative in @('guest-tools\Behavior.Core.ps1','guest-tools\Observe-Behavior.ps1','Analyze-Behavior.ps1','Test-Behavior.ps1')) {
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $relative),[ref]$tokens,[ref]$errors)
    Assert-Behavior ($errors.Count -eq 0) ('syntax: '+$relative)
}
$rootNode=[pscustomobject]@{Key='1:100';ProcessId=1;ParentKey='';Name='demo.exe';CommandLine='demo.exe';Path='C:\Samples\demo.exe';Source='fixture';FirstSeen='2026-01-01T00:00:00Z'}
$data=[pscustomobject]@{SamplePath='C:\Samples\demo.exe';Static=[pscustomobject]@{SHA256=('A'*64);Signature='Valid'};Defender=[pscustomobject]@{ExitCode=$null;Status='not available';Detail='fixture'};Completed=$true;ProcessPolls=5;ProcessTraceAvailable=$true;FileWatchAvailable=$true;ActualDurationSeconds=10;Processes=@($rootNode);Connections=@();FileEvents=@();PersistenceChanges=@();Errors=@();Timeline=@();Assessment=$null}
$assessment=Get-BehaviorAssessment $data $rules
Assert-Behavior ($assessment.SafetyReferenceScore -eq 70 -and $assessment.RiskPoints -eq 0) 'no alerts is capped at 70, never 100'
$data.Errors=@('sensor failure')
$assessment=Get-BehaviorAssessment $data $rules
Assert-Behavior ($assessment.SafetyReferenceScore -eq 50) 'sensor errors degrade the cap'
$data.Errors=@(); $data.Completed=$false
$assessment=Get-BehaviorAssessment $data $rules
Assert-Behavior ($null -eq $assessment.SafetyReferenceScore) 'incomplete observation is N/A'
$data.Completed=$true; $data.Processes=@()
$assessment=Get-BehaviorAssessment $data $rules
Assert-Behavior ($null -eq $assessment.SafetyReferenceScore) 'missing sample process is N/A'
$rootNode.CommandLine='powershell.exe -EncodedCommand fixture DownloadFile Set-MpPreference'
$data.Processes=@($rootNode)
$assessment=Get-BehaviorAssessment $data $rules
Assert-Behavior ($assessment.RiskPoints -eq 75 -and $assessment.SafetyReferenceScore -eq 25) 'risk score is traceable to command evidence'
$data.Processes=@($rootNode,$rootNode)
$duplicate=Get-BehaviorAssessment $data $rules
Assert-Behavior ($duplicate.RiskPoints -eq $assessment.RiskPoints) 'same category is charged once, not per duplicate'
$data.Processes=@($rootNode); $rootNode.CommandLine='demo.exe'
$data.Defender.ExitCode=2
$assessment=Get-BehaviorAssessment $data $rules
Assert-Behavior ($assessment.RiskPoints -eq 10 -and $assessment.Level -ne '高警示') 'Defender code 2 is not a proven malicious verdict'
$data.Defender.ExitCode=$null
$data.PersistenceChanges=@([pscustomobject]@{Kind='RunKey';Key='run';Before='';After='other-background.exe';Attribution='unattributed'})
$assessment=Get-BehaviorAssessment $data $rules
Assert-Behavior ($assessment.RiskPoints -eq 0) 'unrelated persistence change has no strong score'
$data.PersistenceChanges[0].After=$data.SamplePath
$assessment=Get-BehaviorAssessment $data $rules
Assert-Behavior ($assessment.RiskPoints -eq 25) 'direct sample path in new autorun is scored'
$diff=@(Compare-BehaviorPersistence @([pscustomobject]@{Kind='RunKey';Key='x';Value='old'}) @([pscustomobject]@{Kind='RunKey';Key='x';Value='new'}))
Assert-Behavior ($diff.Count -eq 1 -and $diff[0].Before -eq 'old' -and $diff[0].After -eq 'new') 'persistence difference preserves original evidence'
$rootNode.Name='<script>fixture</script>'; $rootNode.CommandLine='<img src=x onerror=alert(1)>'
$data.Assessment=Get-BehaviorAssessment $data $rules
$html=ConvertTo-BehaviorHtml $data
Assert-Behavior (!$html.Contains('<script>') -and $html.Contains('&lt;script&gt;')) 'behavior report escapes process names and command lines'
$rejected=$false
try { & (Join-Path $PSScriptRoot 'guest-tools\Observe-Behavior.ps1') } catch { $rejected=$_.Exception.Message -like '*only inside Windows Sandbox*' }
Assert-Behavior $rejected 'sample launcher refuses accidental host execution'
Write-Host 'All behavior assessment tests passed; fixture commands were never executed.'

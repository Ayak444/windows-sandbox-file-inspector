param([switch]$LargeFile)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'VirusTotal.Core.ps1')
. (Join-Path $PSScriptRoot 'guest-tools\File-Inspector.Core.ps1')
. (Join-Path $PSScriptRoot 'guest-tools\Behavior.Core.ps1')
function Assert-VT($Condition,[string]$Message) { if (!$Condition) { throw "FAIL: $Message" }; Write-Host "PASS: $Message" }
foreach ($relative in @('VirusTotal.Core.ps1','Check-VirusTotal.ps1','guest-tools\Import-VirusTotal.ps1','Test-VirusTotal.ps1')) {
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $relative),[ref]$tokens,[ref]$errors)
    Assert-VT ($errors.Count -eq 0) ('syntax: '+$relative)
}
$hash='a'*64
$fixtureBody=@{data=@{id=$hash;attributes=@{last_analysis_date=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();last_analysis_stats=@{malicious=3;suspicious=0;undetected=60;harmless=2;timeout=1;'type-unsupported'=4};last_analysis_results=@{A=@{engine_name='<script>fixture</script>';category='malicious';result='<img src=x>';engine_update='20261011'}}}}} | ConvertTo-Json -Depth 8
$found=ConvertFrom-VTResponse -Hash $hash -StatusCode 200 -Content $fixtureBody
Assert-VT ($found.Status -eq 'Found' -and $found.Stats.malicious -eq 3 -and $found.Stats.undetected -eq 60) 'existing report preserves distinct engine categories'
Assert-VT ($found.EngineResults[0].Result -eq '<img src=x>') 'raw engine evidence is retained as text'
$html=ConvertTo-VTHtml $found
Assert-VT (!$html.Contains('<script>') -and $html.Contains('&lt;script&gt;')) 'cloud engine names and results are escaped'
foreach ($pair in @(@(404,'NotFound'),@(429,'RateLimited'),@(401,'AuthError'),@(403,'AuthError'),@(503,'RequestError'))) {
    $result=ConvertFrom-VTResponse -Hash $hash -StatusCode $pair[0] -Content '{}'
    Assert-VT ($result.Status -eq $pair[1] -and $null -eq $result.Stats) ('HTTP '+$pair[0]+' cannot masquerade as zero detections')
}
$invalid=ConvertFrom-VTResponse -Hash ('b'*64) -StatusCode 200 -Content $fixtureBody
Assert-VT ($invalid.Status -eq 'InvalidResponse') 'wrong hash response is rejected'
$data=[pscustomobject]@{SamplePath='C:\Samples\demo.exe';Static=[pscustomobject]@{SHA256=$hash;Signature='Valid'};Defender=[pscustomobject]@{ExitCode=$null};Completed=$true;ProcessPolls=5;ProcessTraceAvailable=$true;FileWatchAvailable=$true;Processes=@([pscustomobject]@{Key='1:100';CommandLine='demo.exe'});Connections=@();FileEvents=@();PersistenceChanges=@();Errors=@();VirusTotal=$found}
$rules=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'guest-tools\behavior-rules.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$assessment=Get-BehaviorAssessment $data $rules
Assert-VT ($assessment.RiskPoints -eq 25) 'few malicious engine hits are weighted but not declared proof'
$found.Stats.malicious=6
$assessment=Get-BehaviorAssessment $data $rules
Assert-VT ($assessment.RiskPoints -eq 60 -and $assessment.SafetyReferenceScore -eq 40) 'multiple engine hits add transparent adverse evidence'
$found.Stats.malicious=0
$assessment=Get-BehaviorAssessment $data $rules
Assert-VT ($assessment.SafetyReferenceScore -eq 70) 'zero detections never lift the offline cap'
$data.Static.SHA256='b'*64; $found.Stats.malicious=10
$assessment=Get-BehaviorAssessment $data $rules
Assert-VT ($assessment.RiskPoints -eq 0) 'cloud evidence cannot attach to a different hash'
$root=[IO.Path]::GetFullPath($PSScriptRoot)
$fixture=Join-Path $root ('vt-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    $path=Join-Path $fixture 'hello.txt'
    [IO.File]::WriteAllText($path,'hello',[Text.Encoding]::ASCII)
    $local=Get-VTFileHash $path
    Assert-VT ($local.Hash -eq '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824') 'local streaming SHA-256 matches known value'
    $path=Join-Path $fixture 'multi-block.bin'
    $bytes=[byte[]]::new(3145733); for ($index=0;$index -lt $bytes.Length;$index++) { $bytes[$index]=[byte]($index % 251) }
    [IO.File]::WriteAllBytes($path,$bytes)
    $expectedHasher=[Security.Cryptography.SHA256]::Create()
    try { $expected=[BitConverter]::ToString($expectedHasher.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() } finally { $expectedHasher.Dispose() }
    $local=Get-VTFileHash $path
    Assert-VT ($local.Hash -eq $expected -and $local.Bytes -eq $bytes.Length) 'streaming hash spans multiple buffers and final partial block'
    if ($LargeFile) {
        $path=Join-Path $fixture 'over-2gb.txt'
        $stream=[IO.File]::Create($path)
        try { $stream.SetLength([long]2147483649) } finally { $stream.Dispose() }
        $local=Get-VTFileHash $path
        $static=Get-FileInspection (Get-Item -LiteralPath $path) $fixture
        Assert-VT ($local.Bytes -gt 2147483648 -and $static.SHA256.ToLowerInvariant() -eq $local.Hash) 'actual file over 2 GB is hashed by both modes without size rejection'
    }
} finally {
    $absolute=[IO.Path]::GetFullPath($fixture)
    if (!$absolute.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture cleanup path' }
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
Write-Host 'VirusTotal adapter tests passed. No cloud request or user file upload was performed.'

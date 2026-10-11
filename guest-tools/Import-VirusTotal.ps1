param([Parameter(Mandatory=$true)][string]$Payload)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $PSScriptRoot -ne 'C:\SandboxTools') { throw 'Run this receiver only inside Windows Sandbox.' }
if ($Payload.Length -gt 8192) { throw 'Summary payload too large.' }
. (Join-Path $PSScriptRoot 'Behavior.Core.ps1')
$vt=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload)) | ConvertFrom-Json
if ($vt.Hash -notmatch '^[a-fA-F0-9]{64}$' -or $vt.Status -notin @('Found','NotFound','RateLimited','AuthError','RequestError','InvalidResponse')) { throw 'Invalid summary.' }
if ($vt.Status -eq 'Found') {
    if ($null -eq $vt.Stats) { throw 'Missing engine statistics.' }
    foreach ($property in $vt.Stats.PSObject.Properties) {
        if ($property.Value -isnot [ValueType] -or [double]$property.Value -lt 0 -or [double]$property.Value -gt 1000 -or [double]$property.Value -ne [int]$property.Value) { throw 'Invalid engine count.' }
    }
}
$analysis=Join-Path ([Environment]::GetFolderPath('Desktop')) 'Analysis'
$rules=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'behavior-rules.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$matched=0
foreach ($folder in Get-ChildItem -LiteralPath $analysis -Directory -Filter 'Behavior-*' | Sort-Object LastWriteTime -Descending | Select-Object -First 100) {
    if (($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
    $path=Join-Path $folder.FullName 'behavior.json'
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $file=Get-Item -LiteralPath $path
    if ($file.Length -gt 16777216 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
    $data=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($data.Static.SHA256 -ne $vt.Hash) { continue }
    $data | Add-Member -NotePropertyName VirusTotal -NotePropertyValue $vt -Force
    $data.Assessment=Get-BehaviorAssessment $data $rules
    $data | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
    $htmlPath=Join-Path $folder.FullName 'behavior.html'
    if (Test-Path -LiteralPath $htmlPath) {
        if (((Get-Item -LiteralPath $htmlPath).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
    }
    ConvertTo-BehaviorHtml $data | Set-Content -LiteralPath $htmlPath -Encoding UTF8
    $matched++
}
if ($matched -eq 0) { exit 20 }
Write-Host 'VirusTotal summary attached to matching SHA-256 behavior reports. Refresh the report page.'

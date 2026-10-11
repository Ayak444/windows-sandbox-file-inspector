[CmdletBinding()]
param([string]$Path,[switch]$NoOpen)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'VirusTotal.Core.ps1')
if ($env:USERNAME -eq 'WDAGUtilityAccount') { throw 'Use this entry point on the host. Do not put API keys inside Sandbox.' }
if (!$Path) {
    Add-Type -AssemblyName System.Windows.Forms
    $picker=[Windows.Forms.OpenFileDialog]::new(); $picker.InitialDirectory=(Join-Path $PSScriptRoot 'inbox'); $picker.Title='Select one file to hash locally; only its SHA-256 goes to VirusTotal'
    if ($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { return }; $Path=$picker.FileName
}
$Path=[IO.Path]::GetFullPath($Path)
$file=Get-Item -LiteralPath $Path -Force
if ($file.PSIsContainer) { throw 'Select a file, not a folder.' }
$cursor=$Path
while ($cursor) {
    if (((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Links/junctions are not accepted as hash input.' }
    $cursor=[IO.Path]::GetDirectoryName($cursor)
}
Write-Host 'File content stays local. Only SHA-256 is sent to VirusTotal.'
$hash=Get-VTFileHash $Path
$apiKey=$null
if ($env:VT_API_KEY) { $apiKey=ConvertTo-SecureString $env:VT_API_KEY -AsPlainText -Force }
else { $apiKey=Read-Host 'VirusTotal API key (hidden; not saved)' -AsSecureString }
if ($apiKey.Length -eq 0) { throw 'API key is required. No request sent.' }
$reports=Join-Path $PSScriptRoot 'reports'
try { $result=Invoke-VTHashLookup -Hash $hash.Hash -ApiKey $apiKey -StateDirectory $reports }
finally { if ($null -ne $apiKey) { $apiKey.Dispose(); $apiKey=$null } }
$output=Join-Path $reports ('VirusTotal-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-'+$hash.Hash.Substring(0,12))
New-Item -ItemType Directory -Path $output -Force | Out-Null
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding UTF8
ConvertTo-VTHtml $result | Set-Content -LiteralPath (Join-Path $output 'report.html') -Encoding UTF8
Write-Host ('VirusTotal status: '+$result.Status+'; report: '+(Join-Path $output 'report.html'))
# Only a small result summary is transferred; the API key and file path never enter Sandbox.
$session=Join-Path $PSScriptRoot 'Sandbox-Session.txt'; $cli=Get-Command wsb.exe -ErrorAction SilentlyContinue
if ($null -ne $cli -and (Test-Path -LiteralPath $session)) {
    try {
        $id=[Guid]::Parse((Get-Content -LiteralPath $session -Raw).Trim()).ToString()
        $summary=$result | Select-Object Hash,Status,Detail,FetchedAt,AnalysisAt,AnalysisAgeDays,Stats,DetectedEngines,Url
        $payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($summary | ConvertTo-Json -Depth 6 -Compress)))
        $command='& C:\SandboxTools\Import-VirusTotal.ps1 -Payload '+$payload
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $raw=& $cli.Source exec --id $id --run-as ExistingLogin --command ('powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand '+$encoded) --raw 2>$null
        if ($LASTEXITCODE -eq 0 -and ($raw | Out-String | ConvertFrom-Json).ExitCode -eq 0) { Write-Host 'Matching sandbox behavior report enriched with VirusTotal evidence.' }
        else { Write-Host 'No matching active behavior report; the host report is still available.' }
    } catch { Write-Host 'Sandbox enrichment unavailable; the host report is still available.' }
}
if (!$NoOpen) { Start-Process -FilePath (Join-Path $output 'report.html') }

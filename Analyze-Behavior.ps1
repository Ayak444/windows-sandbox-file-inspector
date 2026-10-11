Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$id=[Guid]::Parse((Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Sandbox-Session.txt') -Raw).Trim()).ToString()
$cli=Get-Command wsb.exe -CommandType Application -ErrorAction Stop
$raw=& $cli.Source list --raw
if ($LASTEXITCODE -ne 0) { throw 'Could not query Sandbox sessions.' }
$sessions=($raw | Out-String | ConvertFrom-Json).WindowsSandboxEnvironments
if (@($sessions | Where-Object { $_.Id -eq $id }).Count -eq 0) { throw 'Start-Sandbox.cmd first and wait for Samples.' }
Write-Host 'Select one EXE in the sandbox file picker and confirm execution. Network remains disabled.'
$raw=& $cli.Source exec --id $id --run-as ExistingLogin --command 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\SandboxTools\Observe-Behavior.ps1' --raw
if ($LASTEXITCODE -ne 0) { throw 'Sandbox desktop unavailable; start it and wait for Samples.' }
$execution=$raw | Out-String | ConvertFrom-Json
if ($execution.ExitCode -ne 0) { throw 'Observation did not complete. See the sandbox console and Analysis\Behavior-*.' }
Write-Host 'Done. Review the report inside the sandbox, then close the sandbox.'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sessionFile = Join-Path $PSScriptRoot 'Sandbox-Session.txt'
if (!(Test-Path -LiteralPath $sessionFile)) { throw 'Start-Sandbox.cmd first, then wait for Samples on the isolated desktop.' }
$id = [Guid]::Parse((Get-Content -LiteralPath $sessionFile -Raw).Trim()).ToString()
$cli = Get-Command wsb.exe -CommandType Application -ErrorAction Stop
$raw = & $cli.Source list --raw
if ($LASTEXITCODE -ne 0) { throw 'Could not query sandbox sessions.' }
$sessions = ($raw | Out-String | ConvertFrom-Json).WindowsSandboxEnvironments
if (@($sessions | Where-Object { $_.Id -eq $id }).Count -eq 0) { throw 'Sandbox is stopped. Start-Sandbox.cmd first and wait for Samples.' }
Write-Host 'Inspecting copies inside Windows Sandbox. No sample will be executed.'
$raw = & $cli.Source exec --id $id --run-as ExistingLogin --command 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\SandboxTools\Inspect-Files.ps1' --raw
if ($LASTEXITCODE -ne 0) { throw 'Cannot access the isolated desktop. Open it and wait for Samples, then retry.' }
$execution = $raw | Out-String | ConvertFrom-Json
if ($execution.ExitCode -ne 0) { throw 'Inspection failed. Check Analysis\File-Check-*\error.txt inside the sandbox.' }
Write-Host 'Inspection complete. The HTML report opens inside the sandbox; see desktop Analysis.'

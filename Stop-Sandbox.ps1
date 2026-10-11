Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sessionFile = Join-Path $PSScriptRoot 'Sandbox-Session.txt'
if (!(Test-Path -LiteralPath $sessionFile -PathType Leaf)) {
    throw 'No recorded session. Use the sandbox window Close button.'
}
$sessionId = [Guid]::Parse((Get-Content -LiteralPath $sessionFile -Raw).Trim()).ToString()
$cli = Get-Command wsb.exe -CommandType Application -ErrorAction Stop
$output = & $cli.Source list --raw
if ($LASTEXITCODE -ne 0) { throw 'Could not list Windows Sandbox sessions.' }
$sessions = ($output | Out-String | ConvertFrom-Json).WindowsSandboxEnvironments
$matching = @($sessions | Where-Object { $_.Id -eq $sessionId })
if ($matching.Count -eq 0) {
    Write-Host 'This folder has no running Sandbox session.'
    return
}
Write-Host 'Stopping this folder''s Sandbox; guest files and unsaved results will be discarded.'
& $cli.Source stop --id $sessionId --raw
if ($LASTEXITCODE -ne 0) { throw "Could not stop Sandbox session: $sessionId" }
$output = & $cli.Source list --raw
if ($LASTEXITCODE -ne 0) { throw 'Stop requested, but final state could not be checked.' }
$remaining = ($output | Out-String | ConvertFrom-Json).WindowsSandboxEnvironments
if (@($remaining | Where-Object { $_.Id -eq $sessionId }).Count -gt 0) {
    throw 'The Sandbox session is still listed. Wait and retry.'
}
Write-Host 'Sandbox session stopped.'

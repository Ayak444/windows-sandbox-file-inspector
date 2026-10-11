Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($PSScriptRoot)
$fixture = Join-Path $root ('inspector-e2e-' + [Guid]::NewGuid().ToString('N'))
$cli = Get-Command wsb.exe -CommandType Application -ErrorAction Stop
$sessionId = $null
try {
    New-Item -ItemType Directory -Path $fixture, (Join-Path $fixture 'inbox') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'Start-Sandbox.ps1') -Destination $fixture
    Copy-Item -LiteralPath (Join-Path $root 'guest-tools') -Destination $fixture -Recurse
    [IO.File]::WriteAllText((Join-Path $fixture 'inbox\hello.txt'), 'Benign tool validation fixture.', [Text.Encoding]::ASCII)
    & (Join-Path $fixture 'Start-Sandbox.ps1')
    $sessionId = (Get-Content -LiteralPath (Join-Path $fixture 'Sandbox-Session.txt') -Raw).Trim()
    $deadline = (Get-Date).AddSeconds(90)
    $ready = $false
    do {
        Start-Sleep -Seconds 4
        $raw = & $cli.Source exec --id $sessionId --run-as ExistingLogin --command 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SandboxTools\Verify-Session.ps1' --raw 2>$null
        if ($LASTEXITCODE -eq 0) {
            $check = $raw | Out-String | ConvertFrom-Json
            $ready = $check.ExitCode -eq 0
        }
    } while (!$ready -and (Get-Date) -lt $deadline)
    if (!$ready) { throw 'Isolated test desktop not ready within 90 seconds.' }
    Write-Host 'PASS: isolated desktop, baseline, network isolation, read-only mappings'
    $raw = & $cli.Source exec --id $sessionId --run-as ExistingLogin --command 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SandboxTools\Test-Guest-Inspector.ps1' --raw
    if ($LASTEXITCODE -ne 0) { throw 'Could not run isolated inspector tests.' }
    $check = $raw | Out-String | ConvertFrom-Json
    if ($check.ExitCode -ne 0) { throw "Isolated inspector validation failed: $($check.ExitCode)" }
    Write-Host 'PASS: actual sandbox inspection, signature call, hash, feature hit, JSON and HTML report'
} finally {
    if ($sessionId) {
        & $cli.Source stop --id $sessionId --raw
        if ($LASTEXITCODE -ne 0) { throw 'Test sandbox stop failed; preserving its fixture.' }
    }
    $absoluteFixture = [IO.Path]::GetFullPath($fixture)
    if (!$absoluteFixture.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture cleanup path' }
    if (Test-Path -LiteralPath $absoluteFixture) { Remove-Item -LiteralPath $absoluteFixture -Recurse -Force }
}

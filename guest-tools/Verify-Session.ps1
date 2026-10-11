Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $PSScriptRoot -ne 'C:\SandboxTools') {
    throw 'Run this script only inside Windows Sandbox, never on the host.'
}
$desktop = [Environment]::GetFolderPath('Desktop')
$analysis = Join-Path $desktop 'Analysis'
$failureCode = 10
try {
    foreach ($path in @((Join-Path $desktop 'Samples'), (Join-Path $analysis 'before.json'), (Join-Path $desktop 'Capture-After.cmd'))) {
        if (!(Test-Path -LiteralPath $path)) { throw "Guest bootstrap incomplete: $path" }
    }
    $failureCode = 11
    $before = Get-Content -LiteralPath (Join-Path $analysis 'before.json') -Raw | ConvertFrom-Json
    if (@($before.CaptureErrors).Count -gt 0) { throw 'Baseline collection reported errors.' }
    $failureCode = 12
    $routes = @(Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') })
    if ($routes.Count -gt 0) { throw 'Unexpected default network route.' }
    $failureCode = 13
    foreach ($mapping in @('C:\Incoming', 'C:\SandboxTools')) {
        $probe = Join-Path $mapping ('.readonly-probe-' + [Guid]::NewGuid().ToString('N'))
        $denied = $false
        try {
            [IO.File]::WriteAllText($probe, 'Read-only verification probe')
        }
        catch {
            $exception = $_.Exception
            while ($null -ne $exception.InnerException) { $exception = $exception.InnerException }
            if ($exception -is [UnauthorizedAccessException] -or
                ($exception -is [IO.IOException] -and ($exception.HResult -band 0xffff) -in @(5, 19))) {
                $denied = $true
            }
            else { throw }
        }
        finally {
            if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Force }
        }
        if (!$denied) { throw "Host mapping allowed writes: $mapping" }
    }
    'PASS: guest bootstrap, baseline, no default network route, both host mappings deny writes.' |
        Set-Content -LiteralPath (Join-Path $analysis 'session-check.txt') -Encoding UTF8
    exit 0
}
catch {
    if (Test-Path -LiteralPath $analysis) {
        $_.Exception.Message | Set-Content -LiteralPath (Join-Path $analysis 'session-check.txt') -Encoding UTF8
    }
    exit $failureCode
}

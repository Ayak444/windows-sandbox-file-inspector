Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($PSScriptRoot)
foreach ($relativePath in @('Start-Sandbox.ps1', 'Verify-Sandbox.ps1', 'Check-Files.ps1', 'Stop-Sandbox.ps1', 'Analyze-Behavior.ps1', 'Test-Behavior.ps1', 'VirusTotal.Core.ps1', 'Check-VirusTotal.ps1', 'Test-VirusTotal.ps1', 'guest-tools\Start-Session.ps1', 'guest-tools\Capture-State.ps1', 'guest-tools\Verify-Session.ps1', 'guest-tools\File-Inspector.Core.ps1', 'guest-tools\Inspect-Files.ps1', 'guest-tools\Behavior.Core.ps1', 'guest-tools\Observe-Behavior.ps1', 'guest-tools\Import-VirusTotal.ps1')) {
    $file = Get-Item -LiteralPath (Join-Path $root $relativePath)
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw ($parseErrors | Out-String) }
}
Write-Host 'PASS: PowerShell syntax'
& (Join-Path $root 'Start-Sandbox.ps1') -CheckOnly
[xml]$cfg = Get-Content -LiteralPath (Join-Path $root 'Offline-Sandbox.wsb') -Raw
foreach ($field in @('vGPU', 'Networking', 'AudioInput', 'VideoInput', 'PrinterRedirection', 'ClipboardRedirection')) {
    if ($cfg.Configuration.$field -ne 'Disable') { throw "Unsafe setting: $field" }
}
if ($cfg.Configuration.ProtectedClient -ne 'Enable') { throw 'Protected Client disabled' }
$mappings = @($cfg.Configuration.MappedFolders.MappedFolder)
if ($mappings.Count -ne 2) { throw 'Unexpected mappings' }
foreach ($mapping in $mappings) {
    if ($mapping.ReadOnly -ne 'true') { throw 'Writable mapping' }
    if (!(Test-Path -LiteralPath $mapping.HostFolder -PathType Container)) { throw 'Missing mapping folder' }
}
if ($mappings[0].HostFolder -ne (Join-Path $root 'inbox') -or
    $mappings[1].HostFolder -ne (Join-Path $root 'guest-tools')) { throw 'Wrong host paths' }
Write-Host 'PASS: offline configuration and only two read-only mappings'
Compare-Object -ReferenceObject @() -DifferenceObject @() | Out-Null
Write-Host 'PASS: empty snapshot comparison'
foreach ($script in @('Start-Session.ps1', 'Capture-State.ps1', 'Verify-Session.ps1', 'Inspect-Files.ps1', 'Observe-Behavior.ps1')) {
    $rejected = $false
    try { & (Join-Path $root ('guest-tools\' + $script)) }
    catch {
        if ($_.Exception.Message -like '*only inside Windows Sandbox*') { $rejected = $true }
        else { throw }
    }
    if (!$rejected) { throw "Guest script did not reject host execution: $script" }
}
Write-Host 'PASS: guest scripts refuse accidental host execution'

# Use an owned fixture, including an XML-special character in the path.
$fixture = Join-Path $root ('sandbox-verify-&-' + [Guid]::NewGuid().ToString('N'))
$link = Join-Path $fixture 'inbox\linked-folder'
try {
    New-Item -ItemType Directory -Path $fixture | Out-Null
    foreach ($name in @('inbox', 'guest-tools', 'target')) {
        New-Item -ItemType Directory -Path (Join-Path $fixture $name) | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $root 'Start-Sandbox.ps1') -Destination $fixture
    & (Join-Path $fixture 'Start-Sandbox.ps1') -CheckOnly
    [xml]$fixtureCfg = Get-Content -LiteralPath (Join-Path $fixture 'Offline-Sandbox.wsb') -Raw
    if ($fixtureCfg.Configuration.MappedFolders.MappedFolder[0].HostFolder -ne (Join-Path $fixture 'inbox')) {
        throw 'XML escaping failed'
    }
    Write-Host 'PASS: relocated folder and XML path escaping'
    New-Item -ItemType Junction -Path $link -Target (Join-Path $fixture 'target') | Out-Null
    $rejected = $false
    try { & (Join-Path $fixture 'Start-Sandbox.ps1') -CheckOnly }
    catch {
        if ($_.Exception.Message -like '*Links/junctions are not allowed*') { $rejected = $true }
        else { throw }
    }
    if (!$rejected) { throw 'Junction was not rejected' }
    Write-Host 'PASS: junction mapping is rejected before launch'
}
finally {
    # Remove the link itself without traversing its target.
    if ([IO.Directory]::Exists($link)) { [IO.Directory]::Delete($link) }
    $resolvedFixture = [IO.Path]::GetFullPath($fixture)
    if (!$resolvedFixture.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Fixture cleanup is outside the workspace'
    }
    if (Test-Path -LiteralPath $resolvedFixture) { Remove-Item -LiteralPath $resolvedFixture -Recurse -Force }
}
Write-Host 'All checks passed. No sample or guest bootstrap was executed.'

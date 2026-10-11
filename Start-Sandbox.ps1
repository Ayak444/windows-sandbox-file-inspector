[CmdletBinding()]
param([switch]$CheckOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Never traverse links: a mapped junction could expose unrelated host files.
function Assert-NoReparsePoints([string]$Path, [switch]$Shallow) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Links/junctions are not allowed in shared folders: $Path"
    }
    if ($item.PSIsContainer -and !$Shallow) {
        foreach ($child in Get-ChildItem -LiteralPath $Path -Force) {
            Assert-NoReparsePoints $child.FullName
        }
    }
}

$root = [IO.Path]::GetFullPath($PSScriptRoot)
Assert-NoReparsePoints $root -Shallow
$inbox = Join-Path $root 'inbox'
$guestTools = Join-Path $root 'guest-tools'
if (!(Test-Path -LiteralPath $inbox -PathType Container) -or
    !(Test-Path -LiteralPath $guestTools -PathType Container)) {
    throw 'The inbox and guest-tools folders must exist next to this script.'
}
Assert-NoReparsePoints $inbox
Assert-NoReparsePoints $guestTools
$safeInbox = [Security.SecurityElement]::Escape($inbox)
$safeTools = [Security.SecurityElement]::Escape($guestTools)
$configuration = @"
<Configuration>
  <vGPU>Disable</vGPU>
  <Networking>Disable</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ProtectedClient>Enable</ProtectedClient>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$safeInbox</HostFolder>
      <SandboxFolder>C:\Incoming</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$safeTools</HostFolder>
      <SandboxFolder>C:\SandboxTools</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\SandboxTools\Start-Session.ps1</Command>
  </LogonCommand>
</Configuration>
"@
# Rebuild every launch; manual edits to the generated WSB are not retained.
$configPath = Join-Path $root 'Offline-Sandbox.wsb'
[IO.File]::WriteAllText($configPath, $configuration, [Text.UTF8Encoding]::new($false))
Write-Host 'Configuration ready: offline, read-only mappings, clipboard/devices disabled.'
if ($CheckOnly) {
    Write-Host 'CheckOnly: no Sandbox or sample was started.'
    return
}
$cli = Get-Command wsb.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -ne $cli) {
    # Avoid the legacy launcher's Store upgrade prompt when the new app is installed.
    $sessionId = [Guid]::NewGuid().ToString()
    & $cli.Source start --id $sessionId --config $configuration --raw
    if ($LASTEXITCODE -ne 0) { throw "Windows Sandbox creation failed (exit $LASTEXITCODE)." }
    [IO.File]::WriteAllText((Join-Path $root 'Sandbox-Session.txt'), $sessionId)
    Start-Process -FilePath $cli.Source -ArgumentList @('connect', '--id', $sessionId) -WindowStyle Hidden
    Write-Host "Sandbox session created: $sessionId. Wait for the isolated desktop."
    return
}
$sandboxExe = Join-Path $env:WINDIR 'System32\WindowsSandbox.exe'
if (!(Test-Path -LiteralPath $sandboxExe -PathType Leaf)) {
    throw 'Windows Sandbox is unavailable. Follow the installation section in README.md.'
}
# This is the interactive isolation window the user requested.
Start-Process -FilePath $sandboxExe -ArgumentList ('"' + $configPath + '"')
Write-Host 'Legacy Windows Sandbox launch requested; desktop readiness is not yet verified.'

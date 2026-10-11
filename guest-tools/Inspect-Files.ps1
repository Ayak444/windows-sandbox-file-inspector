[CmdletBinding()]
param([string]$Path, [switch]$NoOpen)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $PSScriptRoot -ne 'C:\SandboxTools') {
    throw 'Run this tool only inside Windows Sandbox, never on the host.'
}
. (Join-Path $PSScriptRoot 'File-Inspector.Core.ps1')
$desktop = [Environment]::GetFolderPath('Desktop')
$samples = [IO.Path]::GetFullPath((Join-Path $desktop 'Samples'))
if (!$Path) { $Path = $samples }
$fullPath = [IO.Path]::GetFullPath($Path)
if ($fullPath -ne $samples -and !$fullPath.StartsWith($samples + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Inspect only files inside the sandbox desktop Samples folder.' }
if (!(Test-Path -LiteralPath $fullPath)) { throw 'Samples not ready. Wait for sandbox initialization.' }
$cursor = $fullPath
while ($cursor.Length -ge $samples.Length) {
    $entry = Get-Item -LiteralPath $cursor -Force
    if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Links and junctions are not accepted as inspection paths.' }
    if ($cursor -eq $samples) { break }
    $cursor = [IO.Path]::GetDirectoryName($cursor)
}
$output = Join-Path $desktop ('Analysis\File-Check-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,6))
New-Item -ItemType Directory -Path $output -Force | Out-Null
try {
    $inventory = Get-InspectionFiles -Path $fullPath
    $results = [Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($file in $inventory.Files) {
        $index++
        Write-Progress -Activity 'Inspecting files (no sample execution)' -Status "$index / $($inventory.Files.Count): $($file.Name)" -PercentComplete (($index / [Math]::Max(1,$inventory.Files.Count)) * 100)
        $item = Get-FileInspection -File $file -Root $samples
        $results.Add($item)
    }
    Write-Progress -Activity 'Inspecting files (no sample execution)' -Completed
    $defender = Get-DefenderScan -Path $fullPath -OutputDirectory $output
    $report = [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o'); Root = $fullPath; Gaps = $inventory.Gaps
        Defender = $defender; Files = @($results.ToArray())
    }
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding UTF8
    $html = Join-Path $output 'report.html'
    ConvertTo-InspectionHtml $report | Set-Content -LiteralPath $html -Encoding UTF8
    $html | Set-Content -LiteralPath (Join-Path $desktop 'Analysis\Latest-File-Report.txt') -Encoding UTF8
    Write-Host "Report: $html"
    if (!$NoOpen) {
        try { Start-Process -FilePath $html }
        catch { Write-Warning "Report created, but no HTML viewer opened. Open $html inside the sandbox." }
    }
} catch {
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $output 'error.txt') -Encoding UTF8
    throw
}

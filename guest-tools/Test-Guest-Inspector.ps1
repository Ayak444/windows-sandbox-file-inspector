Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $PSScriptRoot -ne 'C:\SandboxTools') { throw 'Only run inside Windows Sandbox.' }
$desktop = [Environment]::GetFolderPath('Desktop')
$fixture = Join-Path $desktop 'Samples\Inspector-Demo'
New-Item -ItemType Directory -Path $fixture -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $fixture 'hello.txt'), 'hello', [Text.Encoding]::ASCII)
[IO.File]::WriteAllText((Join-Path $fixture 'review.ps1'), '# Invoke-Expression FromBase64String; benign test text, never executed', [Text.Encoding]::ASCII)
try {
    & 'C:\SandboxTools\Inspect-Files.ps1' -Path $fixture -NoOpen
    $latest = (Get-Content -LiteralPath (Join-Path $desktop 'Analysis\Latest-File-Report.txt') -Raw).Trim()
    $report = Get-Content -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($latest)) 'report.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if (@($report.Files).Count -ne 2) { exit 21 }
    $text = @($report.Files | Where-Object { $_.Name -like '*hello.txt' })[0]
    if ($text.SHA256 -ne '2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824') { exit 22 }
    $script = @($report.Files | Where-Object { $_.Name -like '*review.ps1' })[0]
    if ($script.Findings.Count -eq 0 -or $script.Signature -eq '不適用') { exit 23 }
    if (!(Test-Path -LiteralPath $latest)) { exit 24 }
    if ($report.Defender.Status -eq '未掃描' -and !$report.Defender.Detail) { exit 25 }
    exit 0
} catch { exit 26 }

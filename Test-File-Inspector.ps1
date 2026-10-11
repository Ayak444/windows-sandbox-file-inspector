Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'guest-tools\File-Inspector.Core.ps1')
function Assert($Condition, [string]$Message) { if (!$Condition) { throw "FAIL: $Message" }; Write-Host "PASS: $Message" }
$root = [IO.Path]::GetFullPath($PSScriptRoot)
$fixture = Join-Path $root ('inspector-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    foreach ($relative in @('guest-tools\File-Inspector.Core.ps1','guest-tools\Inspect-Files.ps1','Check-Files.ps1','Test-File-Inspector.ps1')) {
        $tokens = $null; $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $root $relative), [ref]$tokens, [ref]$errors)
        Assert ($errors.Count -eq 0) "syntax: $relative"
    }
    [IO.File]::WriteAllText((Join-Path $fixture 'hello.txt'), 'hello', [Text.Encoding]::ASCII)
    $normal = Get-FileInspection (Get-Item -LiteralPath (Join-Path $fixture 'hello.txt')) $fixture
    if (!$normal.SHA256) { Write-Host ($normal | ConvertTo-Json -Depth 5) }
    Assert ($normal.SHA256 -eq '2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824') 'known SHA-256'
    Assert ($normal.Findings.Count -eq 0) 'benign text has no rule hits'
    [IO.File]::WriteAllBytes((Join-Path $fixture 'picture.txt'), [byte[]](77,90,0,0))
    $disguised = Get-FileInspection (Get-Item -LiteralPath (Join-Path $fixture 'picture.txt')) $fixture
    Assert (($disguised.Findings -join ' ') -match '副檔名不一致') 'executable header disguised as text'
    $marker = Join-Path $fixture 'EXECUTED.txt'
    $scriptPath = Join-Path $fixture 'fixture.ps1'
    [IO.File]::WriteAllText($scriptPath, "[IO.File]::WriteAllText('$marker','executed')`r`n# Invoke-Expression FromBase64String", [Text.Encoding]::ASCII)
    $script = Get-FileInspection (Get-Item -LiteralPath $scriptPath) $fixture
    Assert (($script.Findings -join ' ') -match '動態執行') 'script feature rule'
    Assert (!(Test-Path -LiteralPath $marker)) 'inspector never executes sample scripts'
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zipPath = Join-Path $fixture 'fixture.zip'
    $zip = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        [void]$zip.CreateEntry('../outside.txt')
        [void]$zip.CreateEntry('word/vbaProject.bin')
        [void]$zip.CreateEntry('run.js')
    } finally { $zip.Dispose() }
    $archive = Get-FileInspection (Get-Item -LiteralPath $zipPath) $fixture
    Assert (($archive.Findings -join ' ') -match '越出目的') 'ZIP traversal detection without extraction'
    Assert (($archive.Findings -join ' ') -match 'VBA') 'Office macro indicator'
    Assert (($archive.Findings -join ' ') -match '可執行項目') 'archive executable entry'
    [IO.File]::WriteAllBytes((Join-Path $fixture 'fixture.rar'), [byte[]](82,97,114,33,26,7,0))
    $rar = Get-FileInspection (Get-Item -LiteralPath (Join-Path $fixture 'fixture.rar')) $fixture
    Assert (($rar.Limits -join ' ') -match '未展開') 'RAR coverage gap is explicit'
    $limited = Get-FileInspection (Get-Item -LiteralPath (Join-Path $fixture 'hello.txt')) $fixture -MaxHashBytes 1
    Assert (!$limited.SHA256 -and $limited.Limits.Count -gt 0) 'hash budget marks incomplete coverage'
    $inventory = Get-InspectionFiles $fixture -MaxFiles 2
    Assert ($inventory.Files.Count -eq 2 -and $inventory.Gaps.Count -gt 0) 'file count limit is visible'
    $report = [pscustomobject]@{
        GeneratedAt = 'test'; Gaps = @(); Files = @([pscustomobject]@{Name='<script>alert(1)</script>';Bytes=1;Type='test';Signature='test';Signer='';SHA256='';Findings=@('<img src=x>');Limits=@()})
        Defender = [pscustomobject]@{Status='未掃描';Detail='fixture';SignatureUpdated='';Log='<script>bad()</script>'}
    }
    $html = ConvertTo-InspectionHtml $report
    Assert (!$html.Contains('<script>') -and $html.Contains('&lt;script&gt;')) 'HTML escapes untrusted filenames and scan logs'
    Assert ($html.Contains('未掃描') -and $html.Contains('不會判定')) 'report never claims a safety verdict'
    $rejected = $false
    try { & (Join-Path $root 'guest-tools\Inspect-Files.ps1') } catch { $rejected = $_.Exception.Message -like '*only inside Windows Sandbox*' }
    Assert $rejected 'main inspector refuses host execution'
    Write-Host 'Inspector tests passed. Only owned benign fixtures were read.'
} finally {
    $absoluteFixture = [IO.Path]::GetFullPath($fixture)
    if (!$absoluteFixture.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture cleanup path' }
    Remove-Item -LiteralPath $absoluteFixture -Recurse -Force
}

Set-StrictMode -Version Latest

function Get-InspectionFiles {
    param([string]$Path, [int]$MaxFiles = 2000)
    $stack = [Collections.Generic.Stack[string]]::new()
    $stack.Push([IO.Path]::GetFullPath($Path))
    $files = [Collections.Generic.List[object]]::new()
    $gaps = [Collections.Generic.List[string]]::new()
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $gaps.Add("略過連結／junction：$current")
                continue
            }
            if ($item.PSIsContainer) {
                foreach ($child in Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop) { $stack.Push($child.FullName) }
            } else {
                if ($files.Count -ge $MaxFiles) { $gaps.Add("超過 $MaxFiles 個檔案上限；其餘檔案未檢查。"); break }
                $files.Add($item)
            }
        } catch { $gaps.Add("無法讀取 $current ：$($_.Exception.Message)") }
    }
    [pscustomobject]@{ Files = @($files.ToArray()); Gaps = @($gaps.ToArray()) }
}

function Get-FileInspection {
    param([IO.FileInfo]$File, [string]$Root, [long]$MaxHashBytes = [long]::MaxValue)
    $findings = [Collections.Generic.List[string]]::new()
    $limits = [Collections.Generic.List[string]]::new()
    $result = [ordered]@{
        Name = $File.FullName.Substring($Root.TrimEnd('\').Length).TrimStart('\')
        Bytes = $File.Length; SHA256 = ''; Type = '未辨識'; Signature = '不適用'; Signer = ''
        Findings = @(); Limits = @()
    }
    try {
        if ($File.Length -le $MaxHashBytes) {
            $hashStream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $hasher = [Security.Cryptography.SHA256]::Create()
            try { $result.SHA256 = [BitConverter]::ToString($hasher.ComputeHash($hashStream)).Replace('-','') }
            finally { $hasher.Dispose(); $hashStream.Dispose() }
        }
        else { $limits.Add('超過單檔／本次總雜湊額度；未計算 SHA-256。') }
        $stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $buffer = [byte[]]::new(65536)
            $count = $stream.Read($buffer, 0, $buffer.Length)
        } finally { $stream.Dispose() }
        $hex = [BitConverter]::ToString($buffer, 0, [Math]::Min($count, 12))
        $extension = $File.Extension.ToLowerInvariant()
        $executables = @('.exe','.dll','.sys','.scr','.com','.cpl','.ocx')
        $scripts = @('.ps1','.psm1','.bat','.cmd','.vbs','.vbe','.js','.jse','.wsf','.hta')
        if ($hex.StartsWith('4D-5A')) {
            $result.Type = 'MZ 可執行檔標頭'
            if ($extension -notin $executables) { $findings.Add('可執行檔標頭與副檔名不一致。') }
        } elseif ($hex.StartsWith('50-4B-03-04') -or $hex.StartsWith('50-4B-05-06')) {
            $result.Type = 'ZIP／Office／其他 ZIP 容器'
            $limits.Add('只檢查 ZIP 目錄；未解壓或逐一檢查封裝內的檔案內容。')
            Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
            $archive = [IO.Compression.ZipFile]::OpenRead($File.FullName)
            try {
                if ($archive.Entries.Count -gt 5000) { $limits.Add('ZIP 超過 5000 個項目；略過目錄分析。') }
                else {
                    $expanded = [long]0
                    foreach ($entry in $archive.Entries) {
                        $name = $entry.FullName.Replace('\','/')
                        if ($name -match '(^/|(^|/)\.\.(/|$)|^[a-zA-Z]:)') { $findings.Add('ZIP 內含越出目的資料夾的路徑。') }
                        if ($name -match '(?i)(^|/)vbaProject\.bin$') { $findings.Add('ZIP／Office 容器內含 VBA 巨集。') }
                        if ([IO.Path]::GetExtension($name).ToLowerInvariant() -in ($executables + $scripts + @('.lnk','.msi'))) {
                            $findings.Add("壓縮檔內含可執行項目：$name")
                        }
                        if ($entry.Length -gt 1073741824 -and ($entry.CompressedLength -eq 0 -or $entry.Length / [Math]::Max([long]1,$entry.CompressedLength) -gt 1000)) {
                            $findings.Add('ZIP 項目解壓後體積與壓縮比例異常。')
                        }
                        $expanded += $entry.Length
                    }
                    if ($expanded -gt 10737418240) { $findings.Add('ZIP 宣告解壓總量超過 10 GB。') }
                }
            } finally { $archive.Dispose() }
        } elseif ($hex.StartsWith('52-61-72-21')) {
            $result.Type = 'RAR 壓縮檔'; $limits.Add('RAR 內容未展開；請在沙箱內解壓後重新檢查。')
        } elseif ($hex.StartsWith('37-7A-BC-AF-27-1C')) {
            $result.Type = '7z 壓縮檔'; $limits.Add('7z 內容未展開；請在沙箱內解壓後重新檢查。')
        } elseif ($hex.StartsWith('25-50-44-46')) {
            $result.Type = 'PDF'; $limits.Add('未分析 PDF 的內嵌物件、JavaScript 或閱讀器漏洞。')
            if ($extension -ne '.pdf') { $findings.Add('PDF 標頭與副檔名不一致。') }
        } elseif ($hex.StartsWith('D0-CF-11-E0-A1-B1-1A-E1')) {
            $result.Type = 'OLE／舊式 Office／MSI 容器'; $limits.Add('未分析 OLE 內嵌物件或巨集。')
        } elseif ($hex.StartsWith('89-50-4E-47')) { $result.Type = 'PNG' }
        elseif ($hex.StartsWith('FF-D8-FF')) { $result.Type = 'JPEG' }
        elseif ($extension -in $scripts) {
            $result.Type = '腳本（依副檔名）'
            $limits.Add('腳本僅比對前 64 KiB 的文字特徵；未執行或完整理解邏輯。')
            $text = [Text.Encoding]::UTF8.GetString($buffer, 0, $count)
            if ($count -ge 2 -and $buffer[0] -eq 255 -and $buffer[1] -eq 254) { $text = [Text.Encoding]::Unicode.GetString($buffer, 0, $count) }
            $rules = [ordered]@{
                '編碼／動態執行命令' = '(?i)(-enc(odedcommand)?\b|\bInvoke-Expression\b|\bIEX\b|FromBase64String)'
                '下載／網路請求' = '(?i)(DownloadString|DownloadFile|Invoke-WebRequest|Start-BitsTransfer|https?://)'
                '修改防毒設定' = '(?i)((Set|Add)-MpPreference|DisableRealtimeMonitoring|ExclusionPath)'
                '建立排程或自動啟動項目' = '(?i)(schtasks|Register-ScheduledTask|CurrentVersion[\\/]Run\b)'
            }
            foreach ($rule in $rules.GetEnumerator()) { if ($text -match $rule.Value) { $findings.Add("脚本特徵：$($rule.Key)；合法程式也可能使用。") } }
        } elseif ($extension -in @('.txt','.md','.csv','.json','.xml','.ini','.log')) { $result.Type = '文字／設定檔（依副檔名）' }
        else { $limits.Add('不支援此檔案格式的內容分析。') }
        if ($extension -in @('.lnk','.url','.msi','.iso','.img','.docm','.xlsm','.pptm')) { $findings.Add('此格式可含執行入口、安裝指令或巨集；需要人工檢查。') }
        if ($File.Name -match '(?i)\.(pdf|jpg|png|txt|docx|xlsx)\.(exe|scr|com|bat|cmd|js|vbs)$') { $findings.Add('檔名使用文件／圖片副檔名再加執行副檔名，可能造成誤認。') }
        if ($File.Name -match '[\u202a-\u202e\u2066-\u2069]') { $findings.Add('檔名含會改變顯示順序的 Unicode 控制字元。') }
        if ($extension -in ($executables + $scripts + @('.msi')) -or $result.Type -eq 'MZ 可執行檔標頭') {
            $signature = Get-AuthenticodeSignature -LiteralPath $File.FullName -ErrorAction Stop
            $result.Signature = [string]$signature.Status
            if ($null -ne $signature.SignerCertificate) { $result.Signer = $signature.SignerCertificate.Subject }
            switch ($result.Signature) {
                'HashMismatch' { $findings.Add('簽章雜湊不一致，檔案可能被修改或損毀。') }
                'NotSigned' { $findings.Add('沒有可驗證的數位簽章；這不代表一定是惡意程式。') }
                'Valid' { $limits.Add('有效簽章只代表簽章驗證通過，不能證明程式沒有惡意行為。') }
                default { $limits.Add("數位簽章未驗證通過：$($result.Signature)；離線環境可能缺少信任鏈或撤銷資訊。") }
            }
        }
    } catch { $limits.Add("檢查未完成：$($_.Exception.Message)") }
    $result.Findings = @($findings.ToArray() | Select-Object -Unique)
    $result.Limits = @($limits.ToArray() | Select-Object -Unique)
    [pscustomobject]$result
}

function Get-DefenderScan {
    param([string]$Path, [string]$OutputDirectory, [int]$TimeoutSeconds = 120)
    $result = [ordered]@{ Status = '未掃描'; Detail = ''; ExitCode = $null; SignatureUpdated = ''; Log = '' }
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $result.SignatureUpdated = [string]$status.AntivirusSignatureLastUpdated
        if (!$status.AMServiceEnabled -or !$status.AntivirusEnabled) { $result.Detail = '此隔離環境的 Defender 未啟用；未取得防毒掃描結果。'; return [pscustomobject]$result }
        $base = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
        $candidates = @(Get-ChildItem -LiteralPath $base -Filter MpCmdRun.exe -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        $exe = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
        if ($candidates.Count -gt 0) { $exe = $candidates[0].FullName }
        if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { throw '找不到 MpCmdRun.exe。' }
        $stdout = Join-Path $OutputDirectory 'defender-output.txt'
        $stderr = Join-Path $OutputDirectory 'defender-error.txt'
        # Custom scan only; no remediation, updates, uploads or network are enabled by this tool.
        $arguments = '-Scan -ScanType 3 -File "' + $Path + '" -DisableRemediation'
        $process = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if (!$process.WaitForExit($TimeoutSeconds * 1000)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $result.Status = '未完成'; $result.Detail = 'Defender 掃描超過 120 秒；沒有完整結果。'
        } else {
            $process.Refresh(); $result.ExitCode = $process.ExitCode
            # Exit 2 is ambiguous: detection OR scanning error, never a proven malicious verdict.
            if ($process.ExitCode -eq 0) { $result.Status = '掃描完成（結束碼 0）'; $result.Detail = '仍需閱讀掃描紀錄；結束碼 0 本身不構成檔案安全證明。' }
            elseif ($process.ExitCode -eq 2) { $result.Status = '偵測或掃描錯誤'; $result.Detail = '結束碼 2 可能是偵測、需要處理或掃描錯誤；請查看原始紀錄。' }
            else { $result.Status = '掃描失敗'; $result.Detail = "Defender 結束碼：$($process.ExitCode)" }
        }
        $result.Log = ([string](Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue) + "`r`n" + [string](Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue))
    } catch { $result.Detail = "未取得 Defender 掃描結果：$($_.Exception.Message)" }
    [pscustomobject]$result
}

function ConvertTo-InspectionHtml {
    param($Report)
    function Encode-ReportText($Value) { [Net.WebUtility]::HtmlEncode([string]$Value) }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append(@'
<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>檔案安全檢查報告</title><style>
body{background:#f3f5f8;color:#17243a;font:16px/1.65 'Segoe UI',sans-serif;margin:0}main{max-width:1050px;margin:36px auto;padding:0 24px}h1{font-size:30px}h2{font-size:21px}.card,details{background:white;padding:22px;margin:16px 0;border:1px solid #dce2ec;border-radius:12px}.notice{background:#fff3ce;border-left:5px solid #d99500;padding:16px}.tag{background:#edf1f7;border-radius:5px;padding:3px 8px;font-size:13px}summary{cursor:pointer;overflow-wrap:anywhere}.warn{color:#9b4400}.muted{color:#5c6879}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f8;padding:12px}code{overflow-wrap:anywhere}ul{padding-left:24px}p{overflow-wrap:anywhere}
</style></head><body><main><h1>檔案安全檢查報告</h1><div class="notice"><strong>這份報告不會判定「安全」。</strong>未命中規則、有效簽章或防毒沒有偵測，都不能證明檔案沒有惡意行為。待測檔案未被執行。</div>
'@)
    [void]$builder.Append('<section class="card"><p>檢查時間：' + (Encode-ReportText $Report.GeneratedAt) + '</p><p>已檢查 ' + $Report.Files.Count + ' 個檔案；' + @($Report.Files | Where-Object { $_.Findings.Count -gt 0 }).Count + ' 個檔案需要注意。</p><p class="muted">內容特徵檢查範圍有限；請查看每個檔案的限制。報告僅存在於隔離環境，關閉沙箱後會丟棄。</p>')
    foreach ($gap in $Report.Gaps) { [void]$builder.Append('<p class="warn">' + (Encode-ReportText $gap) + '</p>') }
    [void]$builder.Append('</section><section class="card"><h2>Defender 防毒掃描</h2><p><strong>' + (Encode-ReportText $Report.Defender.Status) + '</strong></p><p>' + (Encode-ReportText $Report.Defender.Detail) + '</p><p>病毒碼更新時間：' + (Encode-ReportText $Report.Defender.SignatureUpdated) + '</p><details><summary>原始掃描紀錄</summary><pre>' + (Encode-ReportText $Report.Defender.Log) + '</pre></details></section><h2>檔案明細</h2>')
    foreach ($file in $Report.Files) {
        $label = '未命中規則；不代表安全'
        if ($file.Findings.Count -gt 0) { $label = '需要注意／人工確認' }
        [void]$builder.Append('<details><summary><strong>' + (Encode-ReportText $file.Name) + '</strong> <span class="tag">' + (Encode-ReportText $label) + '</span></summary><p>格式：' + (Encode-ReportText $file.Type) + ' · 大小：' + $file.Bytes + ' bytes</p><p>簽章：' + (Encode-ReportText $file.Signature) + '</p><p>簽署者：' + (Encode-ReportText $file.Signer) + '</p><p>SHA-256：<code>' + (Encode-ReportText $file.SHA256) + '</code></p><h3>需注意的特徵</h3><ul>')
        foreach ($finding in $file.Findings) { [void]$builder.Append('<li class="warn">' + (Encode-ReportText $finding) + '</li>') }
        [void]$builder.Append('</ul><h3>檢查限制</h3><ul>')
        foreach ($limit in $file.Limits) { [void]$builder.Append('<li>' + (Encode-ReportText $limit) + '</li>') }
        [void]$builder.Append('</ul></details>')
    }
    [void]$builder.Append('</main></body></html>')
    $builder.ToString()
}

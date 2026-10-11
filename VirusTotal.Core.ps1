Set-StrictMode -Version Latest

function Get-VTField($Object,[string]$Name,$Fallback=$null) {
    if ($null -eq $Object) { return $Fallback }
    $property=$Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Fallback }
    $property.Value
}

function Get-VTFileHash {
    param([string]$Path)
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $hasher=[Security.Cryptography.SHA256]::Create()
    try {
        # Fixed memory usage; no application file-size cutoff or archive parsing.
        $buffer=[byte[]]::new(1048576); $readTotal=[long]0
        while (($count=$stream.Read($buffer,0,$buffer.Length)) -gt 0) {
            [void]$hasher.TransformBlock($buffer,0,$count,$buffer,0); $readTotal+=$count
            Write-Progress -Activity 'Computing SHA-256 locally; file content is not uploaded' -Status ([Math]::Round($readTotal/1MB)).ToString() -PercentComplete ([Math]::Min(100,100*$readTotal/[Math]::Max([long]1,$stream.Length)))
        }
        [void]$hasher.TransformFinalBlock([byte[]]::new(0),0,0)
        [pscustomobject]@{Hash=[BitConverter]::ToString($hasher.Hash).Replace('-','').ToLowerInvariant();Bytes=$readTotal}
    } finally { $hasher.Dispose(); $stream.Dispose(); Write-Progress -Activity 'Computing SHA-256 locally; file content is not uploaded' -Completed }
}

function ConvertFrom-VTResponse {
    param([ValidatePattern('^[a-fA-F0-9]{64}$')][string]$Hash,[int]$StatusCode,[string]$Content)
    $report=[ordered]@{Hash=$Hash.ToLowerInvariant();Status='RequestError';Detail='';FetchedAt=(Get-Date).ToUniversalTime().ToString('o');AnalysisAt='';AnalysisAgeDays=$null;Stats=$null;EngineResults=@();DetectedEngines=@();Url='https://www.virustotal.com/gui/file/'+$Hash.ToLowerInvariant();OfflineCompatible=$true}
    switch ($StatusCode) {
        404 { $report.Status='NotFound'; $report.Detail='VirusTotal 沒有此雜湊的既有報告。未上傳、未掃描，不代表安全。'; return [pscustomobject]$report }
        429 { $report.Status='RateLimited'; $report.Detail='VirusTotal 配額／頻率限制；沒有取得本次結果。'; return [pscustomobject]$report }
        401 { $report.Status='AuthError'; $report.Detail='API key 無效或未授權。'; return [pscustomobject]$report }
        403 { $report.Status='AuthError'; $report.Detail='帳號或 API key 沒有查詢權限。'; return [pscustomobject]$report }
    }
    if ($StatusCode -ne 200) { $report.Detail="VirusTotal 回應 HTTP $StatusCode；未取得有效結果。"; return [pscustomobject]$report }
    try {
        $body=$Content | ConvertFrom-Json
        $data=Get-VTField $body data
        if ((Get-VTField $data id '') -ne $Hash) { throw 'Hash mismatch' }
        $attributes=Get-VTField $data attributes
        $stats=Get-VTField $attributes last_analysis_stats
        if ($null -eq $stats) { throw 'Missing analysis stats' }
        $normalized=[ordered]@{}
        foreach ($category in @('malicious','suspicious','undetected','harmless','timeout','confirmed-timeout','failure','type-unsupported')) {
            $value=Get-VTField $stats $category 0
            if ($value -isnot [ValueType] -or [double]$value -lt 0 -or [double]$value -gt 1000 -or [double]$value -ne [int]$value) { throw 'Invalid statistics' }
            $normalized[$category]=[int]$value
        }
        if (($normalized.Values | Measure-Object -Sum).Sum -eq 0) { throw 'No engine results' }
        $report.Stats=[pscustomobject]$normalized
        $timestamp=[long](Get-VTField $attributes last_analysis_date 0)
        if ($timestamp -gt 0) {
            $date=[DateTimeOffset]::FromUnixTimeSeconds($timestamp).UtcDateTime
            $report.AnalysisAt=$date.ToString('o'); $report.AnalysisAgeDays=[Math]::Max(0,[Math]::Floor(((Get-Date).ToUniversalTime()-$date).TotalDays))
        }
        $results=Get-VTField $attributes last_analysis_results
        $rows=[Collections.Generic.List[object]]::new(); $detected=[Collections.Generic.List[string]]::new()
        if ($null -ne $results) {
            foreach ($property in $results.PSObject.Properties | Select-Object -First 300) {
                $item=$property.Value; $category=[string](Get-VTField $item category 'unknown')
                $name=[string](Get-VTField $item engine_name $property.Name)
                $rows.Add([pscustomobject]@{Engine=$name;Category=$category;Result=[string](Get-VTField $item result '');Updated=[string](Get-VTField $item engine_update '')})
                if ($category -in @('malicious','suspicious') -and $detected.Count -lt 10) { $detected.Add($name.Substring(0,[Math]::Min(60,$name.Length))) }
            }
        }
        $report.EngineResults=@($rows.ToArray()); $report.DetectedEngines=@($detected.ToArray())
        $report.Status='Found'; $report.Detail='取得既有多引擎報告；沒有上傳或觸發重新掃描。undetected 只表示未偵測，不能當成 harmless。'
    } catch { $report.Status='InvalidResponse'; $report.Detail='回應缺少有效統計或雜湊不符；不納入評分。'; $report.Stats=$null }
    [pscustomobject]$report
}

function Invoke-VTHashLookup {
    param([ValidatePattern('^[a-fA-F0-9]{64}$')][string]$Hash,[securestring]$ApiKey,[string]$StateDirectory)
    New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    # Serialize this tool's requests and respect the public API's 4/minute limit.
    $lock=[IO.File]::Open((Join-Path $StateDirectory '.vt-request.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $keyPointer=[IntPtr]::Zero
    try {
        $lastPath=Join-Path $StateDirectory '.last-vt-request.txt'
        if (Test-Path -LiteralPath $lastPath) {
            $last=[datetime]::Parse((Get-Content -LiteralPath $lastPath -Raw)).ToUniversalTime()
            $remaining=16-((Get-Date).ToUniversalTime()-$last).TotalSeconds
            if ($remaining -gt 0) { Write-Host 'Waiting for VirusTotal rate limit...'; Start-Sleep -Milliseconds ([int][Math]::Ceiling($remaining*1000)) }
        }
        (Get-Date).ToUniversalTime().ToString('o') | Set-Content -LiteralPath $lastPath -Encoding ASCII
        $keyPointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey)
        $plainKey=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPointer)
        $request=[Net.HttpWebRequest]::Create('https://www.virustotal.com/api/v3/files/'+$Hash.ToLowerInvariant())
        $request.Method='GET'; $request.AllowAutoRedirect=$false; $request.Timeout=30000; $request.ReadWriteTimeout=30000
        $request.Accept='application/json'; $request.UserAgent='Windows-Sandbox-File-Inspector/2'; $request.Headers.Add('x-apikey',$plainKey)
        $plainKey=$null
        $response=$null; $status=0; $content=''
        try { $response=$request.GetResponse() }
        catch [Net.WebException] { if ($null -ne $_.Exception.Response) { $response=$_.Exception.Response } }
        if ($null -ne $response) {
            try {
                $status=[int]$response.StatusCode
                $reader=[IO.StreamReader]::new($response.GetResponseStream())
                try {
                    $buffer=[char[]]::new(4096); $text=[Text.StringBuilder]::new()
                    while (($count=$reader.Read($buffer,0,$buffer.Length)) -gt 0) {
                        if ($text.Length+$count -gt 1048576) { throw 'VirusTotal response too large.' }
                        [void]$text.Append($buffer,0,$count)
                    }
                    $content=$text.ToString()
                } finally { $reader.Dispose() }
            } finally { $response.Dispose() }
        }
        ConvertFrom-VTResponse -Hash $Hash -StatusCode $status -Content $content
    } finally {
        if ($keyPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer) }
        $plainKey=$null; $lock.Dispose()
    }
}

function ConvertTo-VTHtml {
    param($Report)
    function Encode-VTText($Value) { [Net.WebUtility]::HtmlEncode([string]$Value) }
    $html=[Text.StringBuilder]::new()
    [void]$html.Append(@'
<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>VirusTotal 雜湊驗證</title><style>body{background:#101724;color:#e0e8f4;font:16px/1.65 'Segoe UI',sans-serif}main{max-width:1050px;margin:36px auto;padding:24px}section{background:#192335;padding:22px;margin:16px 0;border:1px solid #314158;border-radius:12px}.warn{color:#ffcb75}table{width:100%;border-collapse:collapse}td,th{padding:10px;text-align:left;border-bottom:1px solid #314158}code,td{overflow-wrap:anywhere}a{color:#84d4ff}</style></head><body><main><h1>VirusTotal 雜湊驗證</h1><section><p class="warn">僅查既有報告；沒有上傳檔案或觸發新掃描。偵測比例不是惡意機率。未知、未偵測與安全是不同概念。</p>
'@)
    [void]$html.Append('<p>狀態：<strong>'+ (Encode-VTText $Report.Status) +'</strong></p><p>'+ (Encode-VTText $Report.Detail) +'</p><p>SHA-256：<code>'+ (Encode-VTText $Report.Hash) +'</code></p><p>報告分析時間：'+ (Encode-VTText $Report.AnalysisAt) +' · 查詢時間：'+ (Encode-VTText $Report.FetchedAt) +'</p>')
    if ($Report.Status -eq 'Found') {
        $s=$Report.Stats
        [void]$html.Append('<p>惡意：<strong>'+ $s.malicious +'</strong> · 可疑：'+$s.suspicious+' · 未偵測：'+$s.undetected+' · harmless：'+$s.harmless+'</p><p>超時：'+($s.timeout+$s.'confirmed-timeout')+' · 失敗：'+$s.failure+' · 不支援：'+$s.'type-unsupported'+'</p>')
        if ($null -eq $Report.AnalysisAgeDays -or $Report.AnalysisAgeDays -gt 30) { [void]$html.Append('<p class="warn">報告時間未知或超過 30 天，可能過時。沒有要求重新掃描。</p>') }
    }
    [void]$html.Append('<p><a rel="noreferrer" href="'+(Encode-VTText $Report.Url)+'">查看 VirusTotal 原始頁面（需主機連網）</a></p></section><section><h2>引擎結果</h2><table><tr><th>引擎</th><th>分類</th><th>偵測名稱</th><th>引擎更新日期</th></tr>')
    foreach ($row in $Report.EngineResults) { [void]$html.Append('<tr><td>'+ (Encode-VTText $row.Engine) +'</td><td>'+ (Encode-VTText $row.Category) +'</td><td>'+ (Encode-VTText $row.Result) +'</td><td>'+ (Encode-VTText $row.Updated) +'</td></tr>') }
    [void]$html.Append('</table></section></main></body></html>'); $html.ToString()
}

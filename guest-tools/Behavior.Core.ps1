Set-StrictMode -Version Latest

function Get-BehaviorAssessment {
    param($Data, $Rules)
    $evidence = [Collections.Generic.List[object]]::new()
    function Add-BehaviorEvidence([string]$Category, [string]$Source, [string]$Detail) {
        $rule = @($Rules.categories | Where-Object { $_.id -eq $Category })[0]
        $evidence.Add([pscustomobject]@{ Category=$Category; Points=[int]$rule.points; Title=$rule.title; Source=$Source; Detail=$Detail })
    }
    if ($Data.Static.Signature -eq 'HashMismatch') { Add-BehaviorEvidence signature_mismatch 'Authenticode' $Data.SamplePath }
    elseif ($Data.Static.Signature -eq 'NotSigned') { Add-BehaviorEvidence unsigned 'Authenticode' $Data.SamplePath }
    if ($null -ne $Data.Defender.ExitCode -and $Data.Defender.ExitCode -eq 2) { Add-BehaviorEvidence defender_attention 'Defender' '結束碼 2 不區分偵測與錯誤，沒有確認惡意。' }
    foreach ($process in $Data.Processes) {
        $command = [string]$process.CommandLine
        if ($command -match '(?i)(-enc(odedcommand)?\b|Invoke-Expression|\bIEX\b|FromBase64String)') { Add-BehaviorEvidence encoded_shell $process.Key $command }
        if ($command -match '(?i)(DownloadString|DownloadFile|Invoke-WebRequest|Start-BitsTransfer|curl.+https?://)') { Add-BehaviorEvidence download_command $process.Key $command }
        if ($command -match '(?i)((Set|Add)-MpPreference|DisableRealtimeMonitoring|ExclusionPath)') { Add-BehaviorEvidence security_change_command $process.Key $command }
        if ($command -match '(?i)(schtasks.+/create|Register-ScheduledTask|reg.+add.+CurrentVersion[\\/]Run\b)') { Add-BehaviorEvidence persistence_command $process.Key $command }
    }
    foreach ($change in $Data.PersistenceChanges) {
        if ($change.After -and ([string]$change.After).IndexOf($Data.SamplePath, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Add-BehaviorEvidence persistence_reference $change.Kind $change.After
        }
    }
    foreach ($connection in $Data.Connections) {
        if ($connection.RemoteAddress -notin @('0.0.0.0','::','::1','127.0.0.1') -and
            $connection.RemoteAddress -notlike '127.*') {
            Add-BehaviorEvidence external_connection $connection.ProcessKey ($connection.RemoteAddress + ':' + $connection.RemotePort)
        }
    }
    $drop = @($Data.FileEvents | Where-Object { $_.Kind -in @('Created','Changed','Renamed') -and [IO.Path]::GetExtension($_.Path).ToLowerInvariant() -in @('.exe','.dll','.sys','.scr','.ps1','.bat','.cmd','.vbs','.js') })
    if ($drop.Count -gt 0) { Add-BehaviorEvidence executable_drop 'FileSystemWatcher（時間相關，非程序歸因）' $drop[0].Path }
    $categories = @($evidence | Group-Object Category)
    $risk = 0
    foreach ($category in $categories) { $risk += [int]$category.Group[0].Points }
    $risk = [Math]::Min(100,$risk)
    $cap = [int]$Rules.scoreCap
    if ($Data.Errors.Count -gt 0 -or !$Data.ProcessTraceAvailable -or !$Data.FileWatchAvailable -or $Data.Static.Signature -notin @('Valid','NotSigned','HashMismatch')) { $cap = [int]$Rules.degradedScoreCap }
    $complete = $Data.Completed -and $Data.Processes.Count -gt 0 -and $Data.ProcessPolls -gt 0 -and $Data.Static.SHA256
    $score = $null
    if ($complete) { $score = [Math]::Max(0,[Math]::Min($cap,100-$risk)) }
    $level = '資料不足，無法給分'
    if ($complete) {
        if ($risk -ge 60) { $level = '高警示' }
        elseif ($risk -ge 25) { $level = '中警示' }
        else { $level = '本次離線觀察低警示' }
    } elseif ($risk -ge 60) { $level = '高警示，但觀察不完整' }
    [pscustomobject]@{
        RuleVersion=$Rules.version; SafetyReferenceScore=$score; RiskPoints=$risk; ScoreCap=$cap; Level=$level
        Evidence=@($evidence.ToArray()); ChargedCategories=@($categories | ForEach-Object { $_.Name })
        Explanation='分數為規則參考值，不是安全機率。每類只扣一次；未聯網、無多引擎驗證與無完整核心監控，因此最高 70 分；感測器降級最高 50 分。資料不足時不給分。'
    }
}

function Get-BehaviorPersistence {
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($key in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
        if (Test-Path -LiteralPath $key) {
            foreach ($property in (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).PSObject.Properties) {
                if ($property.Name -notlike 'PS*') { $rows.Add([pscustomobject]@{Kind='RunKey';Key=$key+'\'+$property.Name;Value=[string]$property.Value}) }
            }
        }
    }
    foreach ($task in Get-ScheduledTask -ErrorAction Stop) {
        $rows.Add([pscustomobject]@{Kind='ScheduledTask';Key=$task.TaskPath+$task.TaskName;Value=($task.Actions | Select-Object Execute,Arguments | ConvertTo-Json -Compress)})
    }
    foreach ($service in Get-CimInstance Win32_Service -ErrorAction Stop) {
        $rows.Add([pscustomobject]@{Kind='Service';Key=$service.Name;Value=[string]$service.PathName+'; StartMode='+$service.StartMode})
    }
    @($rows.ToArray())
}

function Compare-BehaviorPersistence {
    param([object[]]$Before, [object[]]$After)
    $old = @{}; $new = @{}
    foreach ($row in $Before) { $old[$row.Kind+'|'+$row.Key]=$row }
    foreach ($row in $After) { $new[$row.Kind+'|'+$row.Key]=$row }
    foreach ($key in @($old.Keys)+@($new.Keys) | Select-Object -Unique) {
        $a = ''; $b = ''
        if ($old.ContainsKey($key)) { $a=$old[$key].Value }
        if ($new.ContainsKey($key)) { $b=$new[$key].Value }
        if ($a -ne $b) { [pscustomobject]@{Kind=$key.Split('|')[0];Key=$key;Before=$a;After=$b;Attribution='時間相關；只有明確樣本路徑引用會計入強線索'} }
    }
}

function ConvertTo-BehaviorHtml {
    param($Data)
    function Encode-BehaviorText($Value) { [Net.WebUtility]::HtmlEncode([string]$Value) }
    $html = [Text.StringBuilder]::new()
    [void]$html.Append(@'
<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>離線行為分析</title><style>
body{margin:0;background:#101724;color:#e0e8f4;font:15px/1.65 'Segoe UI',sans-serif}main{max-width:1150px;margin:auto;padding:32px 24px}h1{font-size:32px;margin-bottom:8px}h2{font-size:21px}.card{background:#192335;border:1px solid #314158;padding:22px;border-radius:12px;margin:18px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}.big{font-size:36px;font-weight:700;color:#76cef7}.muted{color:#aab8cd}.warning{border-left:4px solid #e4b95c;padding:14px;background:#342e24}nav{display:flex;gap:18px;flex-wrap:wrap}a{color:#84d4ff}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid #314158;overflow-wrap:anywhere}pre,code{white-space:pre-wrap;overflow-wrap:anywhere}details{padding:8px;border:1px solid #314158;border-radius:5px}summary{cursor:pointer}.tree ul{border-left:1px solid #55718b;padding-left:24px}.scroll{overflow:auto;max-height:650px}.pill{background:#314158;padding:3px 8px;border-radius:5px}.positive{color:#ffcb75}
</style></head><body><main><h1>離線行為分析</h1><p class="muted">單一樣本 · 程序樹 · 行為時間線 · 規則評分</p><nav><a href="#score">評分</a><a href="#tree">程序樹</a><a href="#timeline">時間線</a><a href="#persistence">自動啟動</a><a href="#network">網路</a><a href="#coverage">觀察完整度</a></nav><div class="card warning">安全參考分不是「安全機率」。這是離線、有限感測器的實驗性分析，未提供 ANY.RUN 的完整核心／HTTP 監控或 VirusTotal 多引擎驗證。</div>
'@)
    $assessment = $Data.Assessment
    $score = 'N/A'; if ($null -ne $assessment.SafetyReferenceScore) { $score=[string]$assessment.SafetyReferenceScore+' / 100' }
    [void]$html.Append('<section id="score" class="card"><div class="grid"><div><span class="muted">安全參考分數</span><div class="big">'+$score+'</div></div><div><span class="muted">風險等級</span><h2>'+ (Encode-BehaviorText $assessment.Level) +'</h2></div><div>觀察秒數<div class="big">'+[Math]::Round($Data.ActualDurationSeconds)+'</div></div><div>樣本程序樹<div class="big">'+$Data.Processes.Count+'</div></div></div><p>'+ (Encode-BehaviorText $assessment.Explanation) +'</p><p>本次最高分：'+$assessment.ScoreCap+' · 規則版本：'+ (Encode-BehaviorText $assessment.RuleVersion) +'</p><p>樣本：'+ (Encode-BehaviorText $Data.SamplePath) +'<br>SHA-256：<code>'+ (Encode-BehaviorText $Data.Static.SHA256) +'</code></p><table><tr><th>規則</th><th>扣分</th><th>證據來源與原始值</th></tr>')
    foreach ($row in $assessment.Evidence) { [void]$html.Append('<tr><td>'+ (Encode-BehaviorText $row.Title) +'</td><td>'+ $row.Points +'（同類僅一次）</td><td>'+ (Encode-BehaviorText $row.Source) +'<pre>'+ (Encode-BehaviorText $row.Detail) +'</pre></td></tr>') }
    [void]$html.Append('</table></section><section id="tree" class="card tree"><h2>程序樹</h2><p class="muted">節點包含 PID 與建立時間；父子關係依觀察到的建立事件／輪詢，缺失的父節點會獨立顯示。</p>')
    $seen = @{}
    function Add-BehaviorNode($Node, [int]$Depth) {
        if ($seen.ContainsKey($Node.Key) -or $Depth -gt 32) { return }
        $seen[$Node.Key]=$true
        [void]$html.Append('<li><details open><summary>'+ (Encode-BehaviorText $Node.Name) +' <span class="pill">PID '+$Node.ProcessId+'</span> '+ (Encode-BehaviorText $Node.FirstSeen) +'</summary><p>身分：'+ (Encode-BehaviorText $Node.Key) +'<br>來源：'+ (Encode-BehaviorText $Node.Source) +'<br>路徑：'+ (Encode-BehaviorText $Node.Path) +'</p><pre>'+ (Encode-BehaviorText $Node.CommandLine) +'</pre></details>')
        $children = @($Data.Processes | Where-Object { $_.ParentKey -eq $Node.Key })
        if ($children.Count -gt 0) { [void]$html.Append('<ul>'); foreach ($child in $children) { Add-BehaviorNode $child ($Depth+1) }; [void]$html.Append('</ul>') }
        [void]$html.Append('</li>')
    }
    [void]$html.Append('<ul>')
    foreach ($node in $Data.Processes) { if (!$node.ParentKey) { Add-BehaviorNode $node 0 } }
    foreach ($node in $Data.Processes) { if (!$seen.ContainsKey($node.Key)) { Add-BehaviorNode $node 0 } }
    [void]$html.Append('</ul></section><section id="timeline" class="card"><h2>行為時間線</h2><p class="muted">程序與 TCP 標示樣本程序樹；檔案事件沒有程序歸因，不能直接視為樣本造成。</p><div class="scroll"><table><tr><th>时间（UTC）</th><th>事件</th><th>證據</th></tr>')
    foreach ($row in $Data.Timeline | Sort-Object At) { [void]$html.Append('<tr><td>'+ (Encode-BehaviorText $row.At) +'</td><td>'+ (Encode-BehaviorText $row.Kind) +'</td><td>'+ (Encode-BehaviorText $row.Detail) +'</td></tr>') }
    [void]$html.Append('</table></div></section><section id="persistence" class="card"><h2>自動啟動變化</h2><p class="muted">Run 機碼、排程、服務的前後比對；一般系統差異不會自動當成惡意。</p>')
    foreach ($row in $Data.PersistenceChanges) { [void]$html.Append('<details><summary>'+ (Encode-BehaviorText $row.Key) +'</summary><pre>Before: '+ (Encode-BehaviorText $row.Before) +'&#10;After: '+ (Encode-BehaviorText $row.After) +'</pre><p>'+ (Encode-BehaviorText $row.Attribution) +'</p></details>') }
    [void]$html.Append('</section><section id="network" class="card"><h2>TCP 觀察</h2><p class="warning">沙箱網路關閉。不能觀察正常外網通訊、DNS／HTTP 內容，也無法以 0 連線證明安全。</p><p>樣本程序樹 TCP 端點：'+$Data.Connections.Count+'</p>')
    foreach ($row in $Data.Connections) { [void]$html.Append('<pre>'+ (Encode-BehaviorText ($row | ConvertTo-Json -Compress)) +'</pre>') }
    [void]$html.Append('</section><section id="coverage" class="card"><h2>觀察完整度</h2><p>程序建立事件：'+$Data.ProcessTraceAvailable+' · 檔案監看：'+$Data.FileWatchAvailable+' · 完成觀察：'+$Data.Completed+' · 程序輪詢次數：'+$Data.ProcessPolls+'</p><p>監看範圍：Samples、使用者 Roaming、Local Temp。不是全磁碟／全登錄監控；無程序注入、記憶體、封包或核心防竄改感測器。</p><p>Defender：'+ (Encode-BehaviorText $Data.Defender.Status) +' · '+ (Encode-BehaviorText $Data.Defender.Detail) +'</p>')
    foreach ($errorText in $Data.Errors) { [void]$html.Append('<p class="positive">'+ (Encode-BehaviorText $errorText) +'</p>') }
    [void]$html.Append('<p>短命程序可能只有名稱／PID，查不到命令列；事件遺失、PID 重用、惡意程式停用感測器與沙箱偵測可能影響結果。分數未經惡意／良性樣本資料集校準，僅供排序與人工判讀。</p></section></main></body></html>')
    $html.ToString()
}

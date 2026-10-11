# Windows Sandbox File Inspector

在 Windows Sandbox 裡檢查來源不明的檔案，產生中文 HTML／JSON 報告，並提供手動測試前後的系統狀態比較。

工具會建立離線、主機映射唯讀的隔離環境。靜態模式不執行檔案；新增的行為模式讓你選取並確認執行一個 EXE，記錄程序樹與行為時間線，最後給出可追溯的安全參考分。**分數不是安全機率，也不保證檔案一定安全。**

## 功能

| 功能 | 提供的資訊 |
| --- | --- |
| SHA-256 | 檔案內容雜湊，用於識別與比對版本 |
| 格式與檔名 | 部分檔案標頭、副檔名不一致、雙重副檔名與 Unicode 顯示控制字元 |
| 數位簽章 | Authenticode 狀態、簽署者與簽章雜湊不一致等線索 |
| 腳本特徵 | 部分編碼命令、動態執行、下載、防毒設定與自動啟動特徵 |
| 壓縮檔 | ZIP 目錄中的可執行項目、VBA 巨集線索、越界路徑及異常解壓體積 |
| Defender | 可用時執行自訂掃描，保留結束碼、病毒碼時間與原始紀錄 |
| 前後快照 | 比較程序、服務、排程、TCP 連線與部分自動啟動項目 |
| 啟動與停止 | 拒絕共享資料夾中的符號連結／junction，可停止本專案最近一次工作階段 |

合法程式也可能命中特徵或沒有簽章；有效簽章不能證明沒有惡意行為。靜態報告只列出特徵與限制；行為報告另提供實驗性的規則評分，並保留每項證據。

## 新增：離線行為分析與評分

這個模式採用程序樹與時間線的分析方式，沒有接入 ANY.RUN 或 VirusTotal，也沒有多引擎掃描、完整核心監控、記憶體分析或 HTTP／DNS 封包分析。

1. 把完整程式資料夾放入 `inbox`，啟動新的沙箱。
2. 在沙箱桌面雙擊 **`Analyze-Behavior.cmd`**（或主機的同名入口）。
3. 選取 `Samples` 內的一個 `.exe`，確認在隔離環境執行。
4. 預設觀察 60 秒。你可在這段時間操作程式視窗，讓實際功能發生。
5. 查看自動開啟的 `behavior.html`，再關閉整個沙箱。觀察結束不會自動終止樣本程序。

報告位於沙箱桌面的 `Analysis\Behavior-<時間>-<識別碼>`，包含 `behavior.html`、`behavior.json` 與 Defender 原始紀錄；`Latest-Behavior-Report.txt` 記錄最新報告位置。

報告提供：

- **程序樹**：樣本及觀察到的子程序，包含父節點、PID、建立時間、路徑與能取得的命令列。
- **時間線**：程序建立／停止、檔案變化與樣本程序樹的 TCP 端點。
- **自動啟動**：Run 機碼、排程與服務的前後變化，保留原始值。
- **觀察完整度**：事件感測器可用性、輪詢次數、實際觀察時間、資料略過與收集錯誤。
- **安全參考分／風險等級**：依明確規則扣分，每項可回查原始證據，規則見 `guest-tools/behavior-rules.json`。

### 評分如何計算

`風險點數 = 命中類別的扣分總和（最高 100，同類只扣一次）`。

`安全參考分 = min(本次上限, 100 − 風險點數)`。完整度不足時為 **N/A**，不把沒收集到資料算成零風險。

| 規則 | 扣分 |
| --- | --- |
| 簽章雜湊不一致 | 30 |
| 未簽章，弱線索 | 5 |
| Defender 結束碼 2，偵測／錯誤未區分 | 10 |
| 程序命令含編碼／動態執行 | 25 |
| 程序命令含下載操作 | 15 |
| 程序命令含修改防毒設定 | 35 |
| 程序命令含建立自動啟動操作 | 20 |
| 新增自動啟動值直接引用樣本路徑 | 25 |
| 樣本程序樹觀察到對外 TCP 端點 | 15 |
| 同時段可執行檔變化，未能程序歸因 | 5 |

風險點數 **60 以上為高警示、25–59 為中警示、低於 25 為本次離線觀察低警示**。這些門檻與權重是人工設定，未經良性／惡意樣本資料集校準，不是機率、偵測準確率或公認評級。

離線模式沒有外網行為與多引擎驗證，因此安全參考分**最高 70 分**。感測器缺失、收集錯誤或簽章狀態無法驗證時最高 50 分；觀察沒有完成、沒有樣本程序／程序輪詢或沒有 SHA-256 時不給分。高警示證據仍會列出。

### 動態模式的範圍

程序建立／停止使用 WMI 事件，並以 CIM 輪詢補充資訊；身分以 PID 與建立時間區分，避免只用 PID 對照。檔案監看只涵蓋 `Samples`、使用者 Roaming 與 Local Temp，上限 5000 事件；程序樹上限 512 節點、TCP 1000 記錄、時間線 10000 事件。超出上限會標示缺失。

檔案事件只能說明「同時段發生」，沒有程序歸因。一般背景自動啟動變化不會被當成強證據；只有直接引用樣本路徑時才套用對應規則。即使如此，合法安裝程式也可能符合規則，仍需人工判讀。

沙箱仍關閉網路；TCP 觀察不等於封包擷取，0 連線不能證明安全。短命程序可能來不及取得命令列，某些父子關係也可能缺失。感測器和報告都位於樣本可修改的沙箱內，沒有防竄改保證。

目前僅支援 EXE 啟動。進階使用者可在沙箱內用 `Observe-Behavior.ps1 -SamplePath <Samples內的EXE> -DurationSeconds 120` 指定 10–300 秒觀察窗；其他格式請先使用靜態模式。大於 1 秒的輪詢間隔可能因系統查詢耗時而延長，實際時間會寫入報告。

## 系統需求

- 支援 Windows Sandbox 的 Windows Pro、Enterprise 或 Education 版本；建議 Windows 11 24H2 或更新版本。
- BIOS／UEFI 虛擬化與 Windows Sandbox 功能已啟用。
- 至少 4 GB RAM，建議 8 GB 以上；本專案配置 4096 MB 給沙箱。
- Windows PowerShell 5.1 與系統內建 .NET 元件。
- 主機的 `Check-Files.cmd`、`Stop-Sandbox.cmd` 與完整沙箱測試需要新版官方 `wsb.exe` CLI。

一般操作不需要 Python、第三方 PowerShell 模組或網路掃描服務。Python 僅供開發時處理中文 PowerShell 原始碼的編碼。

尚未啟用沙箱時，可在「開啟或關閉 Windows 功能」中勾選 Windows Sandbox，再依提示重新啟動。也可在**系統管理員 PowerShell** 執行：

```powershell
Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -All -Online -NoRestart
```

啟動器不會自動修改系統功能或重新啟動電腦。詳細需求見 [Microsoft 安裝文件](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install)。

## 快速開始

1. 在 GitHub 選擇 **Code → Download ZIP** 並解壓專案，或使用 Git clone。請先閱讀原始碼，再執行啟動器。
2. 將待測檔案或完整資料夾放入 `inbox`。不要在主機開啟或執行待測檔案。
3. 雙擊主機上的 `Start-Sandbox.cmd`，等待隔離桌面出現 `Samples`。
4. 在**沙箱桌面**雙擊 `Check-Files.cmd`。工具會檢查 `Samples` 裡的副本，並嘗試在沙箱內開啟中文 HTML 報告。
5. 記錄結果後關閉沙箱，丟棄隔離環境。主機 `inbox` 的原始檔案會保留。

新版 CLI 可用時，也能雙擊主機根目錄的 `Check-Files.cmd`；它只把檢查命令送進本專案的沙箱，不在主機掃描或執行待測檔案。

`Samples` 是啟動時建立的副本。修改 `inbox` 後，請停止沙箱再重新啟動；不要在工作階段開著時改動共享資料夾。程式若依賴其他檔案，請放入完整資料夾。

## 檢查報告

結果位於**沙箱桌面**，關閉沙箱後會丟棄：

```text
Analysis/
├── Latest-File-Report.txt       # 最新 HTML 報告的位置
└── File-Check-<時間>-<識別碼>/
    ├── report.html             # 中文報告
    ├── report.json             # 結構化結果
    ├── defender-output.txt     # 有執行 Defender 時產生
    ├── defender-error.txt      # 有執行 Defender 時產生
    └── error.txt               # 工具失敗時的錯誤資訊
```

若報告沒有自動開啟，可在沙箱內手動開啟 `report.html`。報告會對檔名、特徵與掃描紀錄進行 HTML 跳脫，不會把樣本內容當成網頁程式碼執行，也不載入外部資源。

| 標示 | 如何理解 |
| --- | --- |
| 需要注意／人工確認 | 至少命中一項特徵，不等同於已證實是惡意檔案 |
| 未命中規則；不代表安全 | 本工具的有限規則沒有命中 |
| 未掃描／未完成 | 防毒不可用、超時、部分內容略過或檢查失敗 |
| Defender 結束碼 2 | 可能是偵測或掃描錯誤，需查看原始紀錄 |

Defender 在部分沙箱環境中不會啟用。工具會明確呈現未掃描原因，不會視為通過；它不會啟用防毒、更新病毒碼或修改防毒偏好。自訂掃描使用 `-DisableRemediation`，但這不控制系統原本的即時防護行為。

## 手動執行與觀察

如需觀察執行行為，只在沙箱的 `Samples` 中手動開啟或執行樣本：

1. 初始化時會自動建立 `Analysis\before.json`。
2. 在沙箱裡操作一個樣本，可配合工作管理員觀察程序。
3. 雙擊沙箱桌面的 `Capture-After.cmd`，建立 `after.json` 與 `changes.txt`。
4. 在沙箱內的 PowerShell 查看比較結果：

```powershell
Get-Content "$env:USERPROFILE\Desktop\Analysis\changes.txt"
```

`=>` 表示測試後才出現的記錄，`<=` 表示測試前有、測試後沒有的記錄。背景程序也會造成差異；快照不是持續監控，可能漏掉短暫活動與已清除的痕跡。每個樣本建議使用新的沙箱工作階段。

## 隔離設定與關閉

| 項目 | 設定 |
| --- | --- |
| 網路、主機剪貼簿、麥克風、攝影機、印表機、vGPU | 關閉 |
| Protected Client | 開啟 |
| 記憶體 | 4096 MB |
| `inbox` → `C:\Incoming` | 唯讀 |
| `guest-tools` → `C:\SandboxTools` | 唯讀 |
| `Samples` 與 `Analysis` | 只存於隔離環境，停止後丟棄 |

正常關閉時，按 Windows Sandbox 視窗右上角的 **×**，依提示丟棄內容。

若視窗已關閉但沙箱仍占用記憶體，可雙擊主機的 `Stop-Sandbox.cmd`。它透過官方 CLI 停止 `Sandbox-Session.txt` 記錄的最近一次工作階段，不停止其他 ID 的沙箱。沒有 CLI、使用傳統啟動器的環境，請使用沙箱視窗關閉。

沒有可寫入主機的結果映射。需要保留報告畫面時，可使用主機截圖；不要為了匯出可疑產物而改成可寫共享。不要在沙箱中登入個人帳號或加入私人資料。

## 範圍與限制

| 項目 | 上限／行為 |
| --- | --- |
| 檔案清單 | 每次最多 2000 個檔案 |
| SHA-256 | 單檔最多 2 GB，每次總雜湊額度 10 GB |
| 腳本文字 | 只比對前 64 KiB 的部分特徵 |
| ZIP | 最多 5000 個目錄項目，不解壓或逐一分析內部內容 |
| RAR／7z | 不展開內容，需在沙箱內解壓後重新檢查 |
| PDF／OLE | 不完整解析內嵌物件、巨集或閱讀器漏洞 |
| Defender | 最多等候 120 秒，超時記錄未完成 |
| 不支援格式、讀取失敗、額度不足 | 記錄檢查限制或略過原因 |

SHA-256 是識別值，不是可信度評分。網路關閉時，需要連網或會辨識虛擬機的惡意程式可能不發作。樣本執行後也可能修改沙箱內的報告與紀錄。Windows Sandbox 可降低風險，但不能保證抵禦所有漏洞；請保持 Windows 更新。

工具沒有檔案上傳功能，也不啟用沙箱網路。主機原本的防毒、雲端提交與檔案處理行為不由本工具控制。

## 專案結構

```text
.
├── Start-Sandbox.cmd / .ps1          # 產生設定、建立沙箱與連線
├── Check-Files.cmd / .ps1            # 主機檢查入口，只轉送到沙箱
├── Analyze-Behavior.cmd / .ps1       # 選取 EXE、離線執行與行為評分
├── Stop-Sandbox.cmd / .ps1           # 停止最近一次工作階段
├── Verify-Sandbox.ps1               # 設定與啟動防護測試
├── Test-File-Inspector.ps1           # 無害樣本的核心測試
├── Test-Behavior.ps1                 # 評分、資料不足、證據歸因測試
├── Test-Inspector-In-Sandbox.ps1     # 獨立沙箱的完整流程測試
├── prepare-inspector.py             # 開發時處理 UTF-8 BOM
├── inbox/                           # 本機樣本，不提交 Git
└── guest-tools/
    ├── Start-Session.ps1             # 複製樣本、配置桌面與建立基準
    ├── Check-Files.cmd               # 沙箱桌面檢查入口
    ├── Inspect-Files.ps1             # 檢查流程與報告輸出
    ├── File-Inspector.Core.ps1       # 雜湊、特徵、Defender、HTML
    ├── Observe-Behavior.ps1          # EXE 啟動、事件收集與行為報告
    ├── Behavior.Core.ps1             # 證據規則、評分與程序樹報告
    ├── behavior-rules.json           # 可檢視與調整的評分權重
    ├── Capture-State.ps1             # 前後系統快照
    ├── Verify-Session.ps1            # 驗證桌面、路由與唯讀映射
    ├── Test-Guest-Inspector.ps1       # 隔離環境的無害驗證
    └── HOW-TO.txt
```

`Offline-Sandbox.wsb` 與 `Sandbox-Session.txt` 依使用者的實際路徑產生，不納入版本控制。`.gitignore` 排除待測檔案、產生的設定、工作階段資料、測試暫存目錄與本機報告。下載後已包含 `inbox` 的空資料夾標記與操作說明。

## 開發與驗證

在專案根目錄執行：

```powershell
# 核心檢查：只使用自行建立的無害樣本
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-File-Inspector.ps1

# 規則評分、重複證據、背景差異與報告跳脫
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-Behavior.ps1

# 隔離設定、junction 拒絕及主機誤執行防護
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Verify-Sandbox.ps1

# 建立獨立沙箱，測試完成後停止自己的工作階段
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-Inspector-In-Sandbox.ps1
```

完整流程測試只映射自建無害檔案，並在沙箱內編譯及執行無害測試 EXE，驗證子程序、檔案寫入、測試自動啟動引用及行為報告，不測試使用者的 `inbox`。若受限制的環境禁止建立 junction，請在一般 PowerShell 執行設定測試。

中文 PowerShell 原始碼需要保留 UTF-8 BOM，確保 Windows PowerShell 5.1 正確讀取。修改相關檔案後，可使用 Python 3 執行：

```powershell
python .\prepare-inspector.py
```

各入口的 `ExecutionPolicy Bypass` 只套用到該次 PowerShell 程序，不會修改主機全域執行原則。

## 常見問題

**沙箱停止或 Samples 尚未就緒**：先執行 `Start-Sandbox.cmd`，等隔離桌面初始化。啟動器視窗存在不代表桌面已就緒。

**傳統啟動器更新逾時 `0x800705b4`**：新版 CLI 可用時，啟動器會優先使用它。若未安裝新版，依 [官方疑難排解](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-troubleshoot) 檢查主機的 Store／Windows Update；不要為此開啟待測沙箱的網路。

**Defender 未掃描**：查看報告中的原因。部分靜態特徵仍可檢查，但沒有防毒結果，不能當作掃描通過。

**文件或壓縮檔無法開啟**：沙箱可能缺少對應閱讀器或解壓工具。需要時，把可信任的離線安裝程式放入 `inbox`，只在沙箱內安裝。

**桌面初始化失敗**：在沙箱的 `Analysis\bootstrap-error.txt` 查看錯誤。`C:\SandboxTools\Verify-Session.ps1` 可檢查初始化、基準紀錄、預設路由與映射是否拒絕寫入，結果存於 `Analysis\session-check.txt`。

## 參考文件

- [Windows Sandbox 安裝](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install)
- [WSB 設定選項](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
- [官方 CLI](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli)
- [Authenticode 簽章](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)
- [Defender 自訂掃描與結束碼](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus)

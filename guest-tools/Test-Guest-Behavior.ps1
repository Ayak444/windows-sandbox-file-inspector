Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $PSScriptRoot -ne 'C:\SandboxTools') { throw 'Only run inside Windows Sandbox.' }
$desktop=[Environment]::GetFolderPath('Desktop')
$sample=Join-Path $desktop 'Samples\Behavior-Demo.exe'
$source=@'
using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using Microsoft.Win32;
public class BehaviorDemo {
    public static void Main() {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "behavior-demo.txt"), "Benign fixture");
        using (var key=Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")) {
            key.SetValue("InspectorBenignDemo", Process.GetCurrentProcess().MainModule.FileName);
        }
        Process.Start(new ProcessStartInfo("cmd.exe", "/c ping -n 5 127.0.0.1 >nul") { UseShellExecute=false, CreateNoWindow=true });
        Thread.Sleep(5000);
    }
}
'@
try {
    if (Test-Path -LiteralPath $sample) { Remove-Item -LiteralPath $sample -Force }
    Add-Type -TypeDefinition $source -OutputAssembly $sample -OutputType ConsoleApplication
    Remove-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name InspectorBenignDemo -ErrorAction SilentlyContinue
    & 'C:\SandboxTools\Observe-Behavior.ps1' -SamplePath $sample -DurationSeconds 10 -NoOpen
    $latest=(Get-Content -LiteralPath (Join-Path $desktop 'Analysis\Latest-Behavior-Report.txt') -Raw).Trim()
    $report=Get-Content -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($latest)) 'behavior.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if (!$report.Completed) { exit 30 }
    if ($report.Processes.Count -lt 2) { exit 31 }
    if (@($report.Processes | Where-Object { $_.Name -eq 'cmd.exe' -and $_.ParentKey }).Count -eq 0) { exit 32 }
    if (@($report.FileEvents | Where-Object { $_.Path -like '*behavior-demo.txt' }).Count -eq 0) { exit 33 }
    if (@($report.Assessment.Evidence | Where-Object { $_.Category -eq 'persistence_reference' }).Count -eq 0) { exit 34 }
    if ($null -eq $report.Assessment.SafetyReferenceScore -or $report.Assessment.SafetyReferenceScore -gt 70) { exit 35 }
    if (!(Test-Path -LiteralPath $latest)) { exit 36 }
    exit 0
} catch {
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $desktop 'Analysis\behavior-test-error.txt') -Encoding UTF8
    exit 39
}

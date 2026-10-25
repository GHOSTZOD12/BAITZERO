Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class WinChecker {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    public static void Inspect() {
        EnumWindows((hWnd, lParam) => {
            uint pid;
            GetWindowThreadProcessId(hWnd, out pid);
            StringBuilder title = new StringBuilder(512);
            GetWindowText(hWnd, title, 512);
            StringBuilder cls = new StringBuilder(512);
            GetClassName(hWnd, cls, 512);
            bool visible = IsWindowVisible(hWnd);
            string t = title.ToString();
            string c = cls.ToString();
            if (t.Length > 0 || c.Contains("Chrome") || c.Contains("Tauri") || c.Contains("WebView")) {
                if (t.Contains("BaitZero") || t.Contains("Link Protection") || c.Contains("Chrome_WidgetWin_0") || c.Contains("Tauri")) {
                    Console.WriteLine("HWND: 0x{0:X} | PID: {1} | Vis: {2} | Cls: {3} | Title: '{4}'", (long)hWnd, pid, visible, c, t);
                }
            }
            return true;
        }, IntPtr.Zero);
    }
}
'@

Write-Host "=== Processes ==="
$procs = Get-Process -Name "link-protection-system*" -ErrorAction SilentlyContinue
foreach ($p in $procs) {
    Write-Host "PID: $($p.Id) | Name: $($p.ProcessName) | MainWindowTitle: '$($p.MainWindowTitle)' | Path: $($p.Path)"
}

Write-Host "`n=== Windows ==="
[WinChecker]::Inspect()

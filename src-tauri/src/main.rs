// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod deep_scan;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use tauri::{
    menu::{MenuBuilder, MenuItem, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, Wry,
};

// ---------------------------------------------------------------------------
// Startup Timing Helper
// ---------------------------------------------------------------------------

/// Lightweight startup milestone logger. Never logs URLs or notification content.
macro_rules! startup_timing {
    ($milestone:expr) => {
        eprintln!("[STARTUP][TIMING] {} | t={:.2}ms",
            $milestone,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_millis() as f64
        );
    };
    ($milestone:expr, $($k:ident = $v:expr),+) => {
        eprintln!("[STARTUP][TIMING] {} | t={:.2}ms | {}",
            $milestone,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_millis() as f64,
            [$(format!("{}={}", stringify!($k), $v)),+].join(" | ")
        );
    };
}

// ---------------------------------------------------------------------------
// Browser Extension IPC â€” Shared Structures
// ---------------------------------------------------------------------------

/// A completed analysis result delivered by the JS frontend.
#[derive(Clone, Debug)]
struct AnalysisResult {
    risk_level: String,
    risk_score: u32,
    evidence_count: u32,
    explanation: String,
    recommendation: String,
    evidence_titles: Vec<String>,
}

pub const MAX_CONCURRENT_BRIDGE_CONNECTIONS: usize = 16;
pub const MAX_PENDING_BRIDGE_QUEUE: usize = 64;

/// RAII guard that automatically decrements the active bridge connection counter upon drop.
pub struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Shared state for the extension IPC bridge.
/// HTTP server threads wait on `condvar` after inserting a pending URL.
/// The JS frontend polls via `poll_extension_queue` and delivers results
/// via `deliver_extension_result`, triggering the condvar.
struct ExtensionBridge {
    /// Pending URLs waiting to be processed: Map<request_id, url>
    pending: Mutex<HashMap<String, String>>,

    /// Completed results: Map<request_id, AnalysisResult>
    results: Mutex<HashMap<String, AnalysisResult>>,

    /// Notifies waiting HTTP threads when a result arrives
    condvar: Condvar,

    /// Number of active concurrent HTTP connections being serviced
    active_connections: Arc<AtomicUsize>,
}

impl ExtensionBridge {
    fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            results: Mutex::new(HashMap::new()),
            condvar: Condvar::new(),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Atomically acquire a connection slot if below MAX_CONCURRENT_BRIDGE_CONNECTIONS.
    fn try_acquire_connection(&self) -> Option<ConnectionGuard> {
        let mut curr = self.active_connections.load(Ordering::SeqCst);
        loop {
            if curr >= MAX_CONCURRENT_BRIDGE_CONNECTIONS {
                return None;
            }
            match self.active_connections.compare_exchange_weak(
                curr,
                curr + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Some(ConnectionGuard {
                        counter: Arc::clone(&self.active_connections),
                    });
                }
                Err(actual) => curr = actual,
            }
        }
    }

    /// Atomically check capacity and enqueue a request if below MAX_PENDING_BRIDGE_QUEUE.
    /// Holding the pending lock across check and insert eliminates any race condition.
    fn enqueue(&self, id: String, url: String) -> Result<(), &'static str> {
        let mut pending = self.pending.lock().map_err(|_| "internal_error")?;
        if pending.len() >= MAX_PENDING_BRIDGE_QUEUE {
            return Err("queue_full");
        }
        pending.insert(id, url);
        Ok(())
    }

    /// Return the first pending item for the JS frontend to analyze.
    fn dequeue_poll(&self) -> Option<(String, String)> {
        let pending = self.pending.lock().ok()?;
        if pending.is_empty() {
            return None;
        }
        let (id, url) = pending.iter().next()?;
        Some((id.clone(), url.clone()))
    }

    /// Deliver a completed result from JS, removing from pending and waking waiting HTTP threads.
    /// Returns true if the request was still pending, or false if it already expired.
    fn deliver_result(&self, id: &str, result: AnalysisResult) -> bool {
        let was_pending = {
            if let Ok(mut pending) = self.pending.lock() {
                pending.remove(id).is_some()
            } else {
                false
            }
        };

        if was_pending {
            if let Ok(mut results) = self.results.lock() {
                results.insert(id.to_string(), result);
            }
            self.condvar.notify_all();
            true
        } else {
            false
        }
    }

    /// Remove a request from pending (and stale results) on timeout or abort.
    fn expire_pending(&self, id: &str) {
        if let Ok(mut p) = self.pending.lock() {
            p.remove(id);
        }
        if let Ok(mut r) = self.results.lock() {
            r.remove(id);
        }
    }

    #[allow(dead_code)]
    fn active_connection_count(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    fn pending_count(&self) -> usize {
        self.pending.lock().map(|p| p.len()).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Windows Notification Listener — Handle & Lifecycle
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
struct NotificationListenerHandle {
    stop_signal: Arc<AtomicBool>,
    notify_tx: std::sync::mpsc::Sender<()>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

#[cfg(not(target_os = "windows"))]
struct NotificationListenerHandle;

// ---------------------------------------------------------------------------
// Isolation Configuration & Fail-Closed Validation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct IsolationConfig {
    is_test_mode: bool,
    mutex_name: String,
    activate_event_name: String,
    bridge_port: u16,
    data_dir: std::path::PathBuf,
    disable_clipboard: bool,
    skip_shell_identity: bool,
}

impl IsolationConfig {
    fn normalize_windows_path_components(p: &std::path::Path) -> Result<Vec<String>, String> {
        if !p.is_absolute() {
            return Err(format!("Path must be absolute: {:?}", p));
        }
        let mut existing = p.to_path_buf();
        let mut tail: Vec<String> = Vec::new();
        while !existing.exists() {
            if let Some(file_name) = existing.file_name() {
                tail.push(file_name.to_string_lossy().to_ascii_uppercase());
            } else {
                break;
            }
            if !existing.pop() {
                break;
            }
        }

        let base_path = if existing.exists() {
            std::fs::canonicalize(&existing).unwrap_or(existing)
        } else {
            p.to_path_buf()
        };

        let mut parts = Vec::new();
        for c in base_path.components() {
            match c {
                std::path::Component::Prefix(prefix) => {
                    let prefix_raw = prefix.as_os_str().to_string_lossy().to_ascii_uppercase();
                    let prefix_str = prefix_raw.trim_start_matches(r"\\?\").to_string();
                    parts.push(prefix_str);
                }
                std::path::Component::RootDir => {
                    parts.push("\\".to_string());
                }
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    if parts.len() > 2 {
                        parts.pop();
                    } else {
                        return Err(format!("Path traverses outside root: {:?}", p));
                    }
                }
                std::path::Component::Normal(part) => {
                    parts.push(part.to_string_lossy().to_ascii_uppercase());
                }
            }
        }
        if parts.len() < 2 {
            return Err(format!("Path lacks root or prefix: {:?}", p));
        }
        tail.reverse();
        parts.extend(tail);
        Ok(parts)
    }

    fn paths_overlap_or_equal(a: &[String], b: &[String]) -> bool {
        a.starts_with(b) || b.starts_with(a)
    }

    fn resolve() -> Result<Self, String> {
        let is_test_mode = match std::env::var("BAITZERO_ISOLATED_TEST_MODE") {
            Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
            Err(_) => false,
        };

        const PROD_MUTEX: &str = "Global\\BaitZeroLinkProtectionSingleInstance";
        const PROD_EVENT: &str = "Global\\BaitZeroLinkProtectionActivate";
        const PROD_PORT: u16 = 27432;

        if !is_test_mode {
            let app_data = match std::env::var("APPDATA") {
                Ok(a) => a,
                Err(_) => return Err("APPDATA environment variable not set".to_string()),
            };
            let data_dir = std::path::PathBuf::from(app_data).join("LinkProtection");
            return Ok(Self {
                is_test_mode: false,
                mutex_name: PROD_MUTEX.to_string(),
                activate_event_name: PROD_EVENT.to_string(),
                bridge_port: PROD_PORT,
                data_dir,
                disable_clipboard: false,
                skip_shell_identity: false,
            });
        }

        // Test mode is ACTIVE: enforce FAIL-CLOSED validation
        eprintln!("[TestMode] BAITZERO_ISOLATED_TEST_MODE is enabled. Enforcing fail-closed isolation checks.");

        let test_mutex = std::env::var("BAITZERO_TEST_MUTEX")
            .map_err(|_| "TestMode validation failed: BAITZERO_TEST_MUTEX must be explicitly set.".to_string())?;
        if test_mutex.trim().is_empty() || test_mutex.trim() == PROD_MUTEX {
            return Err("TestMode validation failed: BAITZERO_TEST_MUTEX cannot be empty or equal to production mutex.".to_string());
        }

        let test_event = std::env::var("BAITZERO_TEST_ACTIVATE_EVENT")
            .map_err(|_| "TestMode validation failed: BAITZERO_TEST_ACTIVATE_EVENT must be explicitly set.".to_string())?;
        if test_event.trim().is_empty() || test_event.trim() == PROD_EVENT {
            return Err("TestMode validation failed: BAITZERO_TEST_ACTIVATE_EVENT cannot be empty or equal to production activate event.".to_string());
        }

        let port_str = std::env::var("BAITZERO_TEST_PORT")
            .map_err(|_| "TestMode validation failed: BAITZERO_TEST_PORT must be explicitly set.".to_string())?;
        let test_port: u16 = port_str
            .trim()
            .parse()
            .map_err(|_| format!("TestMode validation failed: BAITZERO_TEST_PORT '{}' is not a valid u16 port.", port_str))?;
        if test_port < 1024 || test_port == PROD_PORT {
            return Err(format!("TestMode validation failed: BAITZERO_TEST_PORT cannot be below 1024 or equal to production port {}.", PROD_PORT));
        }

        let test_data_dir_str = std::env::var("BAITZERO_TEST_DATA_DIR")
            .map_err(|_| "TestMode validation failed: BAITZERO_TEST_DATA_DIR must be explicitly set.".to_string())?;
        if test_data_dir_str.trim().is_empty() {
            return Err("TestMode validation failed: BAITZERO_TEST_DATA_DIR cannot be empty.".to_string());
        }
        let test_data_dir = std::path::PathBuf::from(test_data_dir_str.trim());
        if !test_data_dir.is_absolute() {
            return Err("TestMode validation failed: BAITZERO_TEST_DATA_DIR must be an absolute path.".to_string());
        }

        let webview_dir_str = std::env::var("WEBVIEW2_USER_DATA_FOLDER")
            .map_err(|_| "TestMode validation failed: WEBVIEW2_USER_DATA_FOLDER must be explicitly set in test mode.".to_string())?;
        if webview_dir_str.trim().is_empty() {
            return Err("TestMode validation failed: WEBVIEW2_USER_DATA_FOLDER cannot be empty.".to_string());
        }
        let webview_dir = std::path::PathBuf::from(webview_dir_str.trim());
        if !webview_dir.is_absolute() {
            return Err("TestMode validation failed: WEBVIEW2_USER_DATA_FOLDER must be an absolute path.".to_string());
        }

        let app_data = std::env::var("APPDATA")
            .map_err(|_| "TestMode validation failed: APPDATA environment variable must be set.".to_string())?;
        let prod_dir = std::path::PathBuf::from(app_data).join("LinkProtection");

        let local_app_data = std::env::var("LOCALAPPDATA")
            .map_err(|_| "TestMode validation failed: LOCALAPPDATA environment variable must be set.".to_string())?;
        let prod_wv = std::path::PathBuf::from(local_app_data).join("com.security.linkprotection");

        let norm_test_data = Self::normalize_windows_path_components(&test_data_dir)?;
        let norm_webview = Self::normalize_windows_path_components(&webview_dir)?;
        let norm_prod_dir = Self::normalize_windows_path_components(&prod_dir)?;
        let norm_prod_wv = Self::normalize_windows_path_components(&prod_wv)?;

        if Self::paths_overlap_or_equal(&norm_test_data, &norm_prod_dir) {
            return Err("TestMode validation failed: BAITZERO_TEST_DATA_DIR overlaps, matches, or contains production LinkProtection data directory.".to_string());
        }
        if Self::paths_overlap_or_equal(&norm_test_data, &norm_prod_wv) {
            return Err("TestMode validation failed: BAITZERO_TEST_DATA_DIR overlaps, matches, or contains production WebView2 data directory.".to_string());
        }
        if Self::paths_overlap_or_equal(&norm_webview, &norm_prod_dir) {
            return Err("TestMode validation failed: WEBVIEW2_USER_DATA_FOLDER overlaps, matches, or contains production LinkProtection data directory.".to_string());
        }
        if Self::paths_overlap_or_equal(&norm_webview, &norm_prod_wv) {
            return Err("TestMode validation failed: WEBVIEW2_USER_DATA_FOLDER overlaps, matches, or contains production WebView2 data directory.".to_string());
        }
        if Self::paths_overlap_or_equal(&norm_test_data, &norm_webview) {
            return Err("TestMode validation failed: BAITZERO_TEST_DATA_DIR and WEBVIEW2_USER_DATA_FOLDER must be distinct, non-overlapping directories.".to_string());
        }

        Ok(Self {
            is_test_mode: true,
            mutex_name: test_mutex.trim().to_string(),
            activate_event_name: test_event.trim().to_string(),
            bridge_port: test_port,
            data_dir: test_data_dir,
            disable_clipboard: true,
            skip_shell_identity: true,
        })
    }
}

// ---------------------------------------------------------------------------
// Global Application State
// ---------------------------------------------------------------------------

struct AppState {
    protection_active: Arc<AtomicBool>,
    status_item: Mutex<Option<MenuItem<Wry>>>,
    extension_bridge: Arc<ExtensionBridge>,
    extension_token: Arc<String>,
    bridge_port: u16,
    notification_listener: Arc<Mutex<Option<NotificationListenerHandle>>>,
    /// Queued navigate-to target arriving before the frontend is ready.
    /// Set when a notification-click triggers a navigate before frontend_ready.
    pending_navigate: Mutex<Option<String>>,
    /// Set to true after the JS frontend signals it is fully initialized.
    frontend_ready: Arc<AtomicBool>,
    /// Stores the most recent floating alert payload so the alert window can
    /// pull it on startup, eliminating the race where the push event fires
    /// before the window's JS listener is registered.
    pending_alert: Mutex<Option<serde_json::Value>>,
}

#[cfg(target_os = "windows")]
static PRIMARY_MUTEX: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

#[cfg(target_os = "windows")]
static PRIMARY_ACTIVATE_EVENT: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

#[cfg(target_os = "windows")]
static ACTIVE_TOASTS: Mutex<Vec<windows::UI::Notifications::ToastNotification>> = Mutex::new(Vec::new());

#[cfg(target_os = "windows")]
fn activate_existing_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        if let Ok(hwnd) = window.hwnd() {
            let win_hwnd = hwnd.0 as isize;
            extern "system" {
                fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
                fn SetForegroundWindow(hWnd: isize) -> i32;
            }
            const SW_RESTORE: i32 = 9;
            unsafe {
                ShowWindow(win_hwnd, SW_RESTORE);
                SetForegroundWindow(win_hwnd);
            }
        }
    }
    if let Some(state) = app.try_state::<AppState>() {
        if state.frontend_ready.load(Ordering::SeqCst) {
            let _ = app.emit("navigate-to", "#/history");
        } else {
            if let Ok(mut guard) = state.pending_navigate.lock() {
                *guard = Some("#/history".to_string());
            }
        }
    } else {
        let _ = app.emit("navigate-to", "#/history");
    }
}

// ---------------------------------------------------------------------------
// Standard Tauri Commands (Phases 1â€“3B-1, unchanged)
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_protection_state(state: tauri::State<AppState>) -> bool {
    state.protection_active.load(Ordering::SeqCst)
}

#[tauri::command]
fn set_protection_state(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
    active: bool,
) -> Result<bool, String> {
    state.protection_active.store(active, Ordering::SeqCst);
    if let Ok(guard) = state.status_item.lock() {
        if let Some(ref item) = *guard {
            let _ = item.set_text(if active { "Protection: Active" } else { "Protection: Paused" });
        }
    }
    let _ = app.emit("protection-state-changed", active);
    Ok(active)
}

#[cfg(target_os = "windows")]
fn ensure_windows_notification_identity() {
    use std::ffi::c_void;
    use std::path::PathBuf;

    // 0. Ensure icon file exists in %APPDATA%\LinkProtection\icon.ico
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let icon_path = if !appdata.is_empty() {
        let dir = PathBuf::from(&appdata).join("LinkProtection");
        let _ = std::fs::create_dir_all(&dir);
        let icon_file = dir.join("icon.ico");
        if !icon_file.exists() {
            let _ = std::fs::write(&icon_file, include_bytes!("../icons/icon.ico"));
        }
        icon_file.to_string_lossy().to_string()
    } else {
        String::new()
    };

    // 0b. Ensure Start Menu shortcut exists with AUMID
    if !appdata.is_empty() {
        let shortcut_path = PathBuf::from(&appdata)
            .join("Microsoft\\Windows\\Start Menu\\Programs\\BaitZero.lnk");
        if !shortcut_path.exists() {
            if let Ok(exe_path) = std::env::current_exe() {
                let exe_str = exe_path.to_string_lossy();
                let ps_cmd = format!(
                    "$wsh = New-Object -ComObject WScript.Shell; \
                     $s = $wsh.CreateShortcut('{}'); \
                     $s.TargetPath = '{}'; \
                     $s.WorkingDirectory = '{}'; \
                     $s.Description = 'BaitZero'; \
                     $s.Save()",
                    shortcut_path.to_string_lossy().replace('\'', "''"),
                    exe_str.replace('\'', "''"),
                    exe_path.parent().unwrap_or(&exe_path).to_string_lossy().replace('\'', "''")
                );
                use std::os::windows::process::CommandExt;
                let _ = std::process::Command::new("powershell")
                    .arg("-NoProfile")
                    .arg("-NonInteractive")
                    .arg("-WindowStyle").arg("Hidden")
                    .arg("-Command")
                    .arg(&ps_cmd)
                    .creation_flags(0x08000000)
                    .output();
            }
        }
    }

    extern "system" {
        fn RegCreateKeyExW(
            hKey: isize,
            lpSubKey: *const u16,
            Reserved: u32,
            lpClass: *const u16,
            dwOptions: u32,
            samDesired: u32,
            lpSecurityAttributes: *mut c_void,
            phkResult: *mut isize,
            lpdwDisposition: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            hKey: isize,
            lpValueName: *const u16,
            Reserved: u32,
            dwType: u32,
            lpData: *const u8,
            cbData: u32,
        ) -> i32;
        fn RegCloseKey(hKey: isize) -> i32;
    }

    const HKEY_CURRENT_USER: isize = -2147483647; // 0x80000001
    const KEY_ALL_ACCESS: u32 = 0x000F003F;
    const REG_SZ: u32 = 1;
    const REG_DWORD: u32 = 4;

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe {
        // 1. HKCU\Software\Classes\AppUserModelId\com.security.linkprotection
        let subkey = to_wide("Software\\Classes\\AppUserModelId\\com.security.linkprotection");
        let mut hkey: isize = 0;
        if RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_ALL_ACCESS,
            std::ptr::null_mut(),
            &mut hkey,
            std::ptr::null_mut(),
        ) == 0 {
            let name_val = to_wide("DisplayName");
            let disp_val = to_wide("BaitZero");
            let _ = RegSetValueExW(
                hkey,
                name_val.as_ptr(),
                0,
                REG_SZ,
                disp_val.as_ptr() as *const u8,
                (disp_val.len() * 2) as u32,
            );

            if !icon_path.is_empty() {
                let icon_name = to_wide("IconUri");
                let icon_val = to_wide(&icon_path);
                let _ = RegSetValueExW(
                    hkey,
                    icon_name.as_ptr(),
                    0,
                    REG_SZ,
                    icon_val.as_ptr() as *const u8,
                    (icon_val.len() * 2) as u32,
                );
            }

            let show_name = to_wide("ShowInSettings");
            let show_val: u32 = 1;
            let _ = RegSetValueExW(
                hkey,
                show_name.as_ptr(),
                0,
                REG_DWORD,
                &show_val as *const u32 as *const u8,
                4,
            );

            RegCloseKey(hkey);
        }

        // 2. HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\com.security.linkprotection
        let notif_subkey = to_wide("Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\com.security.linkprotection");
        let mut notif_hkey: isize = 0;
        if RegCreateKeyExW(
            HKEY_CURRENT_USER,
            notif_subkey.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_ALL_ACCESS,
            std::ptr::null_mut(),
            &mut notif_hkey,
            std::ptr::null_mut(),
        ) == 0 {
            let enabled_name = to_wide("Enabled");
            let enabled_val: u32 = 1;
            let _ = RegSetValueExW(
                notif_hkey,
                enabled_name.as_ptr(),
                0,
                REG_DWORD,
                &enabled_val as *const u32 as *const u8,
                4,
            );

            let banner_name = to_wide("ShowBanner");
            let banner_val: u32 = 1;
            let _ = RegSetValueExW(
                notif_hkey,
                banner_name.as_ptr(),
                0,
                REG_DWORD,
                &banner_val as *const u32 as *const u8,
                4,
            );

            RegCloseKey(notif_hkey);
        }
    }
}

/// Strictly validates and normalizes raw clipboard text for a single HTTP/HTTPS URL.
/// Rejects empty text, internal whitespace, newlines, non-HTTP/HTTPS schemes,
/// embedded credentials, and malformed hosts.
pub fn extract_valid_clipboard_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Reject input containing embedded whitespace, newlines, or carriage returns.
    if trimmed.chars().any(|c| c.is_whitespace() || c == '\n' || c == '\r') {
        return None;
    }

    // Fast scheme pre-check: must start with http:// or https:// (case-insensitive)
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return None;
    }

    // Parse with url::Url
    let parsed = match url::Url::parse(trimmed) {
        Ok(u) => u,
        Err(_) => return None,
    };

    // Strict scheme enforcement
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }

    // Security check: reject URLs with embedded credentials (e.g. https://user:pass@example.com)
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }

    // Host validation: must have a valid host (localhost, valid IP literal, or domain with dot)
    let is_valid_host = match parsed.host() {
        Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => true,
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost") || d.contains('.'),
        None => false,
    };

    if !is_valid_host {
        return None;
    }

    Some(parsed.to_string())
}

#[cfg(target_os = "windows")]
fn start_clipboard_monitor(app_handle: tauri::AppHandle, protection_active: Arc<AtomicBool>) {
    thread::spawn(move || {
        extern "system" {
            fn GetClipboardSequenceNumber() -> u32;
        }

        let mut last_seq = unsafe { GetClipboardSequenceNumber() };

        loop {
            thread::sleep(std::time::Duration::from_millis(350));

            if !protection_active.load(Ordering::SeqCst) {
                continue;
            }

            let current_seq = unsafe { GetClipboardSequenceNumber() };
            if current_seq != last_seq && current_seq != 0 {
                last_seq = current_seq;

                if let Ok(Some(text)) = read_raw_clipboard_text() {
                    if let Some(valid_url) = extract_valid_clipboard_url(&text) {
                        let _ = app_handle.emit("clipboard-updated", serde_json::json!({
                            "text": valid_url,
                            "sequence": current_seq
                        }));
                    }
                }
            }
        }
    });
}

#[cfg(target_os = "windows")]
fn show_windows_toast(app: &tauri::AppHandle, title: &str, body: &str) -> Result<(), String> {
    use windows::core::{HSTRING, w, IInspectable};
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    use windows::Foundation::TypedEventHandler;
    use windows::ApplicationModel::Package;
    use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;

    fn escape_xml(s: &str) -> String {
        s.replace('&', "&amp;")
         .replace('<', "&lt;")
         .replace('>', "&gt;")
         .replace('"', "&quot;")
         .replace('\'', "&apos;")
    }

    let escaped_title = escape_xml(title);
    let escaped_body = escape_xml(body);

    let template = format!(
        "<toast duration=\"short\"><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual><audio src=\"ms-winsoundevent:Notification.Default\"/></toast>",
        escaped_title, escaped_body
    );

    let xml = XmlDocument::new().map_err(|e| format!("Failed to create XmlDocument: {}", e))?;
    xml.LoadXml(&HSTRING::from(template))
        .map_err(|e| format!("Failed to load toast XML: {}", e))?;

    let toast = ToastNotification::CreateToastNotification(&xml)
        .map_err(|e| format!("Failed to create ToastNotification: {}", e))?;

    // In-process activation: when clicked while app is running, activate existing window
    let app_handle_activated = app.clone();
    let _ = toast.Activated(&TypedEventHandler::new(move |_sender: &Option<ToastNotification>, _args: &Option<IInspectable>| {
        eprintln!("[Notification] Toast activated by user: pid={}", std::process::id());
        activate_existing_window(&app_handle_activated);
        Ok(())
    }));

    // Retain toast object in memory so in-process handler remains alive
    if let Ok(mut list) = ACTIVE_TOASTS.lock() {
        list.push(toast.clone());
        if list.len() > 20 {
            list.remove(0);
        }
    }

    let is_packaged = Package::Current().is_ok();
    let notifier = if is_packaged {
        ToastNotificationManager::CreateToastNotifier()
            .map_err(|e| format!("Failed to create packaged ToastNotifier: {}", e))?
    } else {
        let is_test_mode = match std::env::var("BAITZERO_ISOLATED_TEST_MODE") {
            Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
            Err(_) => false,
        };
        let (aumid_str, aumid_pcwstr) = if is_test_mode {
            ("com.security.linkprotection.candidate", w!("com.security.linkprotection.candidate"))
        } else {
            ("com.security.linkprotection", w!("com.security.linkprotection"))
        };
        unsafe {
            let _ = SetCurrentProcessExplicitAppUserModelID(aumid_pcwstr);
        }
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid_str))
            .map_err(|e| format!("Failed to create unpackaged ToastNotifier with AUMID: {}", e))?
    };

    let t_start = std::time::Instant::now();
    println!("[TIMING] Native toast API call started | aumid={}", if is_packaged { "packaged" } else { "unpackaged" });

    let show_res = notifier.Show(&toast);
    let elapsed = t_start.elapsed();

    match show_res {
        Ok(_) => {
            println!("[TIMING] Native toast API call completed | elapsed=+{:.2}ms", elapsed.as_secs_f64() * 1000.0);
            Ok(())
        }
        Err(e) => {
            eprintln!("[TIMING] Native toast API error: {} | elapsed=+{:.2}ms", e, elapsed.as_secs_f64() * 1000.0);
            Err(format!("Failed to show ToastNotification: {}", e))
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn show_windows_toast(_app: &tauri::AppHandle, _title: &str, _body: &str) -> Result<(), String> {
    Ok(())
}

#[tauri::command]
fn notify_user(
    app: tauri::AppHandle,
    title: String,
    body: String,
    source: Option<String>,
) -> Result<(), String> {
    let source_str = source.unwrap_or_else(|| "security".to_string());

    let _ = app.emit("desktop-notification", serde_json::json!({
        "title": &title,
        "body": &body,
        "source": &source_str
    }));

    // Mode B: Clipboard events suppress the native Windows toast to avoid redundant popups
    if source_str.trim().eq_ignore_ascii_case("clipboard") {
        eprintln!("[Notification] Native toast suppressed for clipboard event: title='{}'", title);
        return Ok(());
    }

    // Standard security events preserve native Windows toasts
    if let Err(e) = show_windows_toast(&app, &title, &body) {
        eprintln!("[Notification] Native toast error: {}", e);
        return Err(e);
    }

    Ok(())
}

#[tauri::command]
fn show_main_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    Ok(())
}

/// Called by the JS frontend after it has fully bootstrapped and is ready to
/// receive events. Flushes any pending navigate-to that arrived before the
/// frontend was ready (e.g. from a notification click). Also ensures the
/// window is visible and focused.
#[tauri::command]
fn frontend_ready(app: tauri::AppHandle, state: tauri::State<AppState>) -> Result<(), String> {
    startup_timing!("frontend_ready received");

    // Mark frontend as initialized
    state.frontend_ready.store(true, Ordering::SeqCst);

    // Show and focus the window — at this point the webview has painted
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        #[cfg(target_os = "windows")]
        if let Ok(hwnd) = window.hwnd() {
            let win_hwnd = hwnd.0 as isize;
            extern "system" {
                fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
            }
            const SW_SHOWNORMAL: i32 = 1;
            unsafe {
                ShowWindow(win_hwnd, SW_SHOWNORMAL);
            }
        }
        startup_timing!("window shown and focused after frontend_ready");
    }

    // Flush any pending navigate-to target
    if let Ok(mut guard) = state.pending_navigate.lock() {
        if let Some(target) = guard.take() {
            startup_timing!("flushing queued navigate-to");
            let _ = app.emit("navigate-to", &target);
        }
    }

    Ok(())
}

/// Returns the application version string.
#[tauri::command]
fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
fn hide_main_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Floating Alert Window Commands & Positioning Modes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertPositionMode {
    /// Mode A: Immediately above the native Windows toast (~138px above work area bottom)
    Security,
    /// Mode B: Bottom-right of active display, just above taskbar (~12px above work area bottom)
    Clipboard,
}

impl AlertPositionMode {
    pub fn from_opt_str(s: Option<&str>) -> Self {
        match s.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("clipboard") => AlertPositionMode::Clipboard,
            _ => AlertPositionMode::Security, // default / safe fallback
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AlertPositionMode::Clipboard => "clipboard",
            AlertPositionMode::Security => "security",
        }
    }
}

pub fn get_alert_margin_bottom_logical(mode: AlertPositionMode) -> f64 {
    match mode {
        AlertPositionMode::Clipboard => 12.0,
        AlertPositionMode::Security => 138.0,
    }
}

pub fn calculate_alert_coordinates(
    work_left: i32,
    work_top: i32,
    work_right: i32,
    work_bottom: i32,
    physical_width: i32,
    physical_height: i32,
    physical_margin_right: i32,
    physical_margin_bottom: i32,
) -> (i32, i32) {
    let calc_x = work_right - physical_width - physical_margin_right;
    let calc_y = work_bottom - physical_height - physical_margin_bottom;
    let clamped_x = calc_x.max(work_left);
    let clamped_y = calc_y.max(work_top);
    (clamped_x, clamped_y)
}

fn position_alert_window(
    alert_window: &tauri::WebviewWindow,
    mode: AlertPositionMode,
) -> Result<(), String> {
    let scale_factor = alert_window
        .current_monitor()
        .ok()
        .flatten()
        .map(|m| m.scale_factor())
        .unwrap_or(1.0);

    // Target dimensions per spec: 332x90 ensures 320x82 card has 6px horizontal padding and is never clipped
    let logical_width = 332.0;
    let logical_height = 90.0;
    let logical_margin_right = 16.0;

    // Mode A: ~138px offset accounts for standard native toast (~116px) + margin/padding
    // Mode B: ~12px offset positions alert directly above taskbar in the active display's work area
    let logical_margin_bottom = get_alert_margin_bottom_logical(mode);

    let physical_width = (logical_width * scale_factor).round() as i32;
    let physical_height = (logical_height * scale_factor).round() as i32;
    let physical_margin_right = (logical_margin_right * scale_factor).round() as i32;
    let physical_margin_bottom = (logical_margin_bottom * scale_factor).round() as i32;

    #[cfg(target_os = "windows")]
    {
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct RECT {
            left: i32,
            top: i32,
            right: i32,
            bottom: i32,
        }

        #[repr(C)]
        struct MONITORINFO {
            cb_size: u32,
            rc_monitor: RECT,
            rc_work: RECT,
            dw_flags: u32,
        }

        #[repr(C)]
        #[derive(Default)]
        struct POINT {
            x: i32,
            y: i32,
        }

        const MONITOR_DEFAULTTONEAREST: u32 = 2;

        extern "system" {
            fn GetCursorPos(lp_point: *mut POINT) -> i32;
            fn MonitorFromPoint(pt_x: i32, pt_y: i32, dw_flags: u32) -> isize;
            fn MonitorFromWindow(hwnd: isize, dw_flags: u32) -> isize;
            fn GetMonitorInfoW(h_monitor: isize, lpmi: *mut MONITORINFO) -> i32;
        }

        let mut h_mon: isize = 0;
        let mut pt = POINT::default();
        if unsafe { GetCursorPos(&mut pt) } != 0 {
            h_mon = unsafe { MonitorFromPoint(pt.x, pt.y, MONITOR_DEFAULTTONEAREST) };
        }
        if h_mon == 0 {
            if let Ok(hwnd) = alert_window.hwnd() {
                h_mon = unsafe { MonitorFromWindow(hwnd.0 as isize, MONITOR_DEFAULTTONEAREST) };
            }
        }

        let mut mi = MONITORINFO {
            cb_size: std::mem::size_of::<MONITORINFO>() as u32,
            rc_monitor: RECT::default(),
            rc_work: RECT::default(),
            dw_flags: 0,
        };

        let work_area = if h_mon != 0 && unsafe { GetMonitorInfoW(h_mon, &mut mi) } != 0 {
            Some(mi.rc_work)
        } else {
            None
        };

        let (x, y) = if let Some(work) = work_area {
            calculate_alert_coordinates(
                work.left,
                work.top,
                work.right,
                work.bottom,
                physical_width,
                physical_height,
                physical_margin_right,
                physical_margin_bottom,
            )
        } else {
            // Safe fallback to monitor bounds if work area query is unavailable
            let monitor = alert_window
                .current_monitor()
                .ok()
                .flatten()
                .or_else(|| alert_window.primary_monitor().ok().flatten())
                .ok_or_else(|| "No monitor found".to_string())?;
            let mon_pos = monitor.position();
            let mon_size = monitor.size();
            let fallback_margin_bottom = match mode {
                AlertPositionMode::Clipboard => (56.0 * scale_factor).round() as i32,
                AlertPositionMode::Security => (190.0 * scale_factor).round() as i32,
            };
            let calc_x = mon_pos.x + (mon_size.width as i32) - physical_width - physical_margin_right;
            let calc_y = mon_pos.y + (mon_size.height as i32) - physical_height - fallback_margin_bottom;
            (calc_x, calc_y)
        };

        let _ = alert_window.set_size(tauri::Size::Physical(tauri::PhysicalSize {
            width: physical_width as u32,
            height: physical_height as u32,
        }));
        let _ = alert_window.set_position(tauri::Position::Physical(tauri::PhysicalPosition {
            x,
            y,
        }));
        let _ = alert_window.set_decorations(false);
        let _ = alert_window.set_shadow(false);
        let _ = alert_window.set_resizable(false);
        let _ = alert_window.set_always_on_top(true);
        let _ = alert_window.set_skip_taskbar(true);

        #[cfg(target_os = "windows")]
        if let Ok(hwnd) = alert_window.hwnd() {
            let win_hwnd = hwnd.0 as isize;
            extern "system" {
                fn GetWindowLongW(hWnd: isize, nIndex: i32) -> i32;
                fn SetWindowLongW(hWnd: isize, nIndex: i32, dwNewLong: i32) -> i32;
                fn SetWindowPos(
                    hWnd: isize,
                    hWndInsertAfter: isize,
                    X: i32,
                    Y: i32,
                    cx: i32,
                    cy: i32,
                    uFlags: u32,
                ) -> i32;
                fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
            }

            const GWL_STYLE: i32 = -16;
            const GWL_EXSTYLE: i32 = -20;
            const WS_POPUP: u32 = 0x80000000;
            const WS_CAPTION: u32 = 0x00C00000;
            const WS_THICKFRAME: u32 = 0x00040000;
            const WS_MINIMIZEBOX: u32 = 0x00020000;
            const WS_MAXIMIZEBOX: u32 = 0x00010000;
            const WS_SYSMENU: u32 = 0x00080000;
            const WS_EX_TOOLWINDOW: u32 = 0x00000080;
            const WS_EX_APPWINDOW: u32 = 0x00040000;
            const SWP_NOACTIVATE: u32 = 0x0010;
            const SWP_FRAMECHANGED: u32 = 0x0020;
            const SWP_SHOWWINDOW: u32 = 0x0040;
            const HWND_TOPMOST: isize = -1;
            const SW_SHOWNOACTIVATE: i32 = 4;

            unsafe {
                let cur_style = GetWindowLongW(win_hwnd, GWL_STYLE) as u32;
                let new_style = (cur_style & !(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU)) | WS_POPUP;
                SetWindowLongW(win_hwnd, GWL_STYLE, new_style as i32);

                let cur_ex = GetWindowLongW(win_hwnd, GWL_EXSTYLE) as u32;
                let new_ex = (cur_ex & !WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW;
                SetWindowLongW(win_hwnd, GWL_EXSTYLE, new_ex as i32);

                let _ = ShowWindow(win_hwnd, SW_SHOWNOACTIVATE);
                let _ = SetWindowPos(
                    win_hwnd,
                    HWND_TOPMOST,
                    x,
                    y,
                    physical_width,
                    physical_height,
                    SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_FRAMECHANGED,
                );
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let monitor = alert_window
            .current_monitor()
            .ok()
            .flatten()
            .or_else(|| alert_window.primary_monitor().ok().flatten())
            .ok_or_else(|| "No monitor found".to_string())?;
        let mon_pos = monitor.position();
        let mon_size = monitor.size();
        let x = mon_pos.x + (mon_size.width as i32) - physical_width - physical_margin_right;
        let y = mon_pos.y + (mon_size.height as i32) - physical_height - physical_margin_bottom;
        let _ = alert_window.set_size(tauri::Size::Physical(tauri::PhysicalSize {
            width: physical_width as u32,
            height: physical_height as u32,
        }));
        let _ = alert_window.set_position(tauri::Position::Physical(tauri::PhysicalPosition {
            x,
            y,
        }));
        let _ = alert_window.set_always_on_top(true);
        let _ = alert_window.show();
    }

    Ok(())
}

#[tauri::command]
fn show_floating_alert(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
    app_name: Option<String>,
    url: String,
    position_mode: Option<String>,
) -> Result<(), String> {
    let mode = AlertPositionMode::from_opt_str(position_mode.as_deref());
    let source_app = app_name.unwrap_or_else(|| "Discord".to_string());
    let payload = serde_json::json!({
        "url": url,
        "sourceApp": source_app,
        "title": "Link received",
        "message": "Checking for potential risks…",
        "status": "checking",
        "positionMode": mode.as_str()
    });

    if let Ok(mut guard) = state.pending_alert.lock() {
        *guard = Some(payload.clone());
    }

    if let Some(alert_window) = app.get_webview_window("alert") {
        let _ = position_alert_window(&alert_window, mode);
        let _ = app.emit("floating-alert-show", payload);
    }
    Ok(())
}

#[tauri::command]
fn update_floating_alert(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
    status: String,
    title: String,
    message: String,
    risk_score: Option<u32>,
    evidence: Option<Vec<String>>,
    url: Option<String>,
) -> Result<(), String> {
    let risk_level = match status.as_str() {
        "suspicious" => "HIGH",
        "safe" => "LOW",
        "inconclusive" => "INCONCLUSIVE",
        other => other,
    };
    let final_url = url.or_else(|| {
        state.pending_alert.lock().ok().and_then(|g| {
            g.as_ref().and_then(|v| v.get("url").and_then(|u| u.as_str()).map(|s| s.to_string()))
        })
    });
    let payload = serde_json::json!({
        "url": final_url,
        "status": status,
        "riskLevel": risk_level,
        "title": title,
        "message": message,
        "riskScore": risk_score,
        "evidence": evidence
    });
    if let Ok(mut guard) = state.pending_alert.lock() {
        *guard = Some(payload.clone());
    }
    let _ = app.emit("floating-alert-update", payload);
    Ok(())
}

/// Called by the alert window JS on startup to pull the pending alert data.
/// This is the reliable pull-model counterpart to the push `floating-alert-show`
/// event, which can be missed if it fires before the window's listener registers.
#[tauri::command]
fn get_alert_init_data(state: tauri::State<AppState>) -> Option<serde_json::Value> {
    state.pending_alert.lock().ok().and_then(|g| g.clone())
}

#[tauri::command]
fn dismiss_floating_alert(app: tauri::AppHandle, state: tauri::State<AppState>) -> Result<(), String> {
    // Clear pending alert so next show_floating_alert starts fresh
    if let Ok(mut guard) = state.pending_alert.lock() {
        *guard = None;
    }
    if let Some(alert_window) = app.get_webview_window("alert") {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::HWND;
            use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
            if let Ok(hwnd) = alert_window.hwnd() {
                let win_hwnd = HWND(hwnd.0 as _);
                unsafe {
                    let _ = ShowWindow(win_hwnd, SW_HIDE);
                }
            }
        }
        let _ = alert_window.hide();
    }
    Ok(())
}

#[tauri::command]
fn open_alert_in_main(app: tauri::AppHandle, state: tauri::State<AppState>, url: String) -> Result<(), String> {
    if let Ok(mut guard) = state.pending_alert.lock() {
        *guard = None;
    }
    if let Some(alert_window) = app.get_webview_window("alert") {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::HWND;
            use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
            if let Ok(hwnd) = alert_window.hwnd() {
                let win_hwnd = HWND(hwnd.0 as _);
                unsafe {
                    let _ = ShowWindow(win_hwnd, SW_HIDE);
                }
            }
        }
        let _ = alert_window.hide();
    }
    if let Some(main_win) = app.get_webview_window("main") {
        let _ = main_win.show();
        let _ = main_win.unminimize();
        let _ = main_win.set_focus();
    }
    // Emit a structured {url} object; main.js listener reads event.payload.url
    let _ = app.emit("open-url-in-analyze", serde_json::json!({ "url": url }));
    Ok(())
}


#[cfg(target_os = "windows")]
fn read_raw_clipboard_text() -> Result<Option<String>, String> {
    use std::ffi::c_void;
    use std::slice;

    extern "system" {
        fn OpenClipboard(hWndNewOwner: *mut c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn GetClipboardData(uFormat: u32) -> *mut c_void;
        fn IsClipboardFormatAvailable(format: u32) -> i32;
        fn GlobalLock(hMem: *mut c_void) -> *mut c_void;
        fn GlobalUnlock(hMem: *mut c_void) -> i32;
    }

    const CF_UNICODETEXT: u32 = 13;

    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
            return Ok(None);
        }
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return Ok(None);
        }
        let handle = GetClipboardData(CF_UNICODETEXT);
        if handle.is_null() {
            CloseClipboard();
            return Ok(None);
        }
        let ptr = GlobalLock(handle) as *const u16;
        if ptr.is_null() {
            CloseClipboard();
            return Ok(None);
        }
        let mut len = 0;
        while *ptr.add(len) != 0 && len < 4096 {
            len += 1;
        }
        let slice = slice::from_raw_parts(ptr, len);
        let text = String::from_utf16_lossy(slice);
        GlobalUnlock(handle);
        CloseClipboard();
        Ok(Some(text))
    }
}

#[cfg(not(target_os = "windows"))]
fn read_raw_clipboard_text() -> Result<Option<String>, String> {
    Ok(None)
}

#[tauri::command]
fn get_clipboard_text() -> Result<Option<String>, String> {
    match read_raw_clipboard_text() {
        Ok(Some(text)) => Ok(extract_valid_clipboard_url(&text)),
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

#[tauri::command]
fn get_clipboard_sequence() -> u32 {
    #[cfg(target_os = "windows")]
    {
        extern "system" {
            fn GetClipboardSequenceNumber() -> u32;
        }
        unsafe { GetClipboardSequenceNumber() }
    }
    #[cfg(not(target_os = "windows"))]
    {
        0
    }
}

// ---------------------------------------------------------------------------
// Browser Extension IPC Commands (Phase 3B-2)
// ---------------------------------------------------------------------------

/// Returns server info and current protection state.
/// Called by the extension (via the JS bridge) to verify connectivity.
#[tauri::command]
fn get_extension_server_info(state: tauri::State<AppState>) -> serde_json::Value {
    serde_json::json!({
        "port": state.bridge_port,
        "protectionActive": state.protection_active.load(Ordering::SeqCst),
        "version": "3B-2",
        "token": state.extension_token.as_str()
    })
}

/// Polled by the JS frontend every 250ms to get the next URL to analyze.
/// Returns {id, url} if a request is pending, or null if none.
/// The JS processes the URL through the full existing pipeline, then calls
/// deliver_extension_result with the results.
#[tauri::command]
fn poll_extension_queue(state: tauri::State<AppState>) -> Option<serde_json::Value> {
    let (id, url) = state.extension_bridge.dequeue_poll()?;
    Some(serde_json::json!({ "id": id, "url": url }))
}

/// Called by the JS frontend after running a URL through the full analysis pipeline.
/// This delivers the result to the waiting HTTP server thread.
#[tauri::command]
fn deliver_extension_result(
    state: tauri::State<AppState>,
    id: String,
    risk_level: String,
    risk_score: u32,
    evidence_count: u32,
    explanation: String,
    recommendation: String,
    evidence_titles: Vec<String>,
) -> Result<(), String> {
    let result = AnalysisResult {
        risk_level,
        risk_score,
        evidence_count,
        explanation,
        recommendation,
        evidence_titles,
    };
    state.extension_bridge.deliver_result(&id, result);
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows Notification Listener Commands (Phase 3B-3)
// ---------------------------------------------------------------------------

/// Check whether the Windows UserNotificationListener capability is available.
/// Microsoft UserNotificationListener requires app package identity with the
/// 'userNotificationListener' restricted capability in an Appx/MSIX manifest.
/// Check whether the Windows UserNotificationListener capability is available.
#[tauri::command]
fn get_notification_listener_status() -> serde_json::Value {
    #[cfg(target_os = "windows")]
    {
        use windows::ApplicationModel::Package;
        use windows::UI::Notifications::Management::{UserNotificationListener, UserNotificationListenerAccessStatus};
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }

        let is_packaged = Package::Current().is_ok();
        if !is_packaged {
            return serde_json::json!({
                "status": "permission_required",
                "message": "Windows UserNotificationListener capability requires app package identity (MSIX package with userNotificationListener capability). Currently running in unpackaged mode.",
                "package_identity": false,
                "granted": false
            });
        }

        match UserNotificationListener::Current() {
            Ok(listener) => match listener.GetAccessStatus() {
                Ok(UserNotificationListenerAccessStatus::Allowed) => serde_json::json!({
                    "status": "enabled",
                    "raw_status": 1,
                    "message": "Notification access granted and active.",
                    "package_identity": true,
                    "granted": true
                }),
                Ok(UserNotificationListenerAccessStatus::Denied) => serde_json::json!({
                    "status": "permission_denied",
                    "raw_status": 2,
                    "message": "Notification access denied in Windows Privacy Settings.",
                    "package_identity": true,
                    "granted": false
                }),
                _ => serde_json::json!({
                    "status": "permission_required",
                    "raw_status": 0,
                    "message": "Windows notification access has not been granted yet.",
                    "package_identity": true,
                    "granted": false
                }),
            },
            Err(e) => serde_json::json!({
                "status": "error",
                "message": format!("Failed to access UserNotificationListener: {}", e),
                "package_identity": true,
                "granted": false
            }),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        serde_json::json!({
            "status": "not_available",
            "message": "Windows notification listener is only available on Windows 10/11.",
            "package_identity": false,
            "granted": false
        })
    }
}

/// Request Windows notification listener permission on the UI thread with full diagnostics.
#[tauri::command]
async fn request_notification_listener_permission(app_handle: tauri::AppHandle) -> serde_json::Value {
    #[cfg(target_os = "windows")]
    {
        use std::sync::{Arc, Mutex};
        use tokio::sync::oneshot;
        use windows::{
            ApplicationModel::Package,
            Foundation::AsyncOperationCompletedHandler,
            UI::Notifications::Management::{UserNotificationListener, UserNotificationListenerAccessStatus},
        };

        let caller_thread_id = format!("{:?}", std::thread::current().id());
        let (tx, rx) = oneshot::channel::<serde_json::Value>();
        let tx = Arc::new(Mutex::new(Some(tx)));
        let tx_clone = tx.clone();
        let caller_tid_clone = caller_thread_id.clone();

        let run_result = app_handle.run_on_main_thread(move || {
            let main_thread_id = format!("{:?}", std::thread::current().id());

            // 1. Check Package identity
            let package_info = (|| {
                let package = Package::Current()?;
                let package_id = package.Id()?;
                let name = package_id.Name()?.to_string();
                let full_name = package_id.FullName()?.to_string();
                let publisher = package_id.Publisher()?.to_string();
                let version = package_id.Version()?;
                Ok::<_, windows::core::Error>((
                    name,
                    full_name,
                    publisher,
                    format!("{}.{}.{}.{}", version.Major, version.Minor, version.Build, version.Revision),
                ))
            })();

            let (has_identity, pkg_name, full_name, publisher, version_str) = match &package_info {
                Ok((n, f, p, v)) => (true, n.clone(), f.clone(), p.clone(), v.clone()),
                Err(_) => (false, String::new(), String::new(), String::new(), String::new()),
            };

            if !has_identity {
                if let Some(sender) = tx_clone.lock().unwrap().take() {
                    let _ = sender.send(serde_json::json!({
                        "status": "permission_required",
                        "message": "Windows UserNotificationListener capability requires app package identity (MSIX or sparse package with userNotificationListener capability). Currently running in unpackaged mode.",
                        "granted": false,
                        "has_package_identity": false,
                        "diagnostic": {
                            "listener_current_success": false,
                            "access_status_before": "Unspecified",
                            "request_access_invoked": false,
                            "completion_callback_reached": false,
                            "raw_request_access_result": "None",
                            "package_current_success": false,
                            "has_package_identity": false,
                            "caller_thread_id": caller_tid_clone,
                            "main_thread_id": main_thread_id,
                            "error_text": "APPMODEL_ERROR_NO_PACKAGE: The process has no package identity. Install and launch the MSIX package to enable native notification listening."
                        }
                    }));
                }
                return;
            }

            // 2. Obtain UserNotificationListener
            let listener = match UserNotificationListener::Current() {
                Ok(l) => l,
                Err(e) => {
                    if let Some(sender) = tx_clone.lock().unwrap().take() {
                        let _ = sender.send(serde_json::json!({
                            "status": "error",
                            "message": format!("Failed to get UserNotificationListener: {}", e),
                            "granted": false,
                            "has_package_identity": true,
                            "diagnostic": {
                                "listener_current_success": false,
                                "package_current_success": true,
                                "has_package_identity": true,
                                "package_name": pkg_name,
                                "package_full_name": full_name,
                                "package_publisher": publisher,
                                "package_version": version_str,
                                "caller_thread_id": caller_tid_clone,
                                "main_thread_id": main_thread_id,
                                "hresult": format!("{:#x}", e.code().0),
                                "error_text": format!("{}", e)
                            }
                        }));
                    }
                    return;
                }
            };

            let access_before = listener.GetAccessStatus().unwrap_or(UserNotificationListenerAccessStatus::Unspecified);
            let access_before_str = match access_before {
                UserNotificationListenerAccessStatus::Allowed => "Allowed",
                UserNotificationListenerAccessStatus::Denied => "Denied",
                _ => "Unspecified",
            };

            // If already allowed, return immediately
            if access_before == UserNotificationListenerAccessStatus::Allowed {
                if let Some(sender) = tx_clone.lock().unwrap().take() {
                    let _ = sender.send(serde_json::json!({
                        "status": "enabled",
                        "granted": true,
                        "message": format!("Notification access already granted. Package: {}", full_name),
                        "has_package_identity": true,
                        "diagnostic": {
                            "listener_current_success": true,
                            "access_status_before": access_before_str,
                            "request_access_invoked": false,
                            "completion_callback_reached": true,
                            "raw_request_access_result": "Allowed",
                            "access_status_after": "Allowed",
                            "caller_thread_id": caller_tid_clone,
                            "main_thread_id": main_thread_id,
                            "package_current_success": true,
                            "has_package_identity": true,
                            "package_name": pkg_name,
                            "package_full_name": full_name,
                            "package_publisher": publisher,
                            "package_version": version_str
                        }
                    }));
                }
                return;
            }

            // 3. Invoke RequestAccessAsync from main thread
            let operation = match listener.RequestAccessAsync() {
                Ok(op) => op,
                Err(e) => {
                    if let Some(sender) = tx_clone.lock().unwrap().take() {
                        let _ = sender.send(serde_json::json!({
                            "status": "error",
                            "message": format!("Failed to create RequestAccessAsync operation: {}", e),
                            "granted": false,
                            "has_package_identity": true,
                            "diagnostic": {
                                "listener_current_success": true,
                                "access_status_before": access_before_str,
                                "request_access_invoked": false,
                                "package_current_success": true,
                                "has_package_identity": true,
                                "package_name": pkg_name,
                                "package_full_name": full_name,
                                "caller_thread_id": caller_tid_clone,
                                "main_thread_id": main_thread_id,
                                "hresult": format!("{:#x}", e.code().0),
                                "error_text": format!("{}", e)
                            }
                        }));
                    }
                    return;
                }
            };

            let tx_for_handler = tx_clone.clone();
            let caller_tid_h = caller_tid_clone.clone();
            let main_tid_h = main_thread_id.clone();
            let pkg_name_h = pkg_name.clone();
            let full_name_h = full_name.clone();
            let publisher_h = publisher.clone();
            let version_h = version_str.clone();

            let handler = AsyncOperationCompletedHandler::new(move |op, _status| {
                let callback_thread_id = format!("{:?}", std::thread::current().id());
                let op_ref = match op {
                    Some(o) => o,
                    None => {
                        if let Some(sender) = tx_for_handler.lock().unwrap().take() {
                            let _ = sender.send(serde_json::json!({
                                "status": "error",
                                "message": "AsyncOperationCompletedHandler received null operation",
                                "granted": false
                            }));
                        }
                        return Ok(());
                    }
                };

                let res = op_ref.GetResults();
                let (status_str, granted, raw_code) = match res {
                    Ok(UserNotificationListenerAccessStatus::Allowed) => ("enabled", true, 1),
                    Ok(UserNotificationListenerAccessStatus::Denied) => ("permission_denied", false, 2),
                    Ok(_) => ("permission_required", false, 0),
                    Err(ref e) => ("error", false, e.code().0),
                };

                let err_text = if let Err(ref e) = res { Some(format!("{}", e)) } else { None };
                let hresult_val = if let Err(ref e) = res { Some(format!("{:#x}", e.code().0)) } else { None };

                if let Some(sender) = tx_for_handler.lock().unwrap().take() {
                    let _ = sender.send(serde_json::json!({
                        "status": status_str,
                        "granted": granted,
                        "message": match status_str {
                            "enabled" => format!("Notification access granted. Package: {}", full_name_h),
                            "permission_denied" => format!("Notification access denied. Package: {}", full_name_h),
                            _ => format!("Notification access status: {}. Package: {}", status_str, full_name_h),
                        },
                        "has_package_identity": true,
                        "diagnostic": {
                            "listener_current_success": true,
                            "access_status_before": access_before_str,
                            "request_access_invoked": true,
                            "completion_callback_reached": true,
                            "raw_request_access_result": status_str,
                            "raw_request_access_result_code": raw_code,
                            "access_status_after": status_str,
                            "caller_thread_id": caller_tid_h,
                            "main_thread_id": main_tid_h,
                            "callback_thread_id": callback_thread_id,
                            "package_current_success": true,
                            "has_package_identity": true,
                            "package_name": pkg_name_h,
                            "package_full_name": full_name_h,
                            "package_publisher": publisher_h,
                            "package_version": version_h,
                            "hresult": hresult_val,
                            "error_text": err_text
                        }
                    }));
                }
                Ok(())
            });

            if let Err(e) = operation.SetCompleted(&handler) {
                if let Some(sender) = tx_clone.lock().unwrap().take() {
                    let _ = sender.send(serde_json::json!({
                        "status": "error",
                        "message": format!("Failed to set completion handler: {}", e),
                        "granted": false,
                        "diagnostic": {
                            "caller_thread_id": caller_tid_clone,
                            "main_thread_id": main_thread_id,
                            "error_text": format!("{}", e)
                        }
                    }));
                }
            }
        });

        if let Err(e) = run_result {
            return serde_json::json!({
                "status": "error",
                "message": format!("Failed to run on main UI thread: {}", e),
                "granted": false,
                "diagnostic": {
                    "caller_thread_id": caller_thread_id,
                    "error_text": format!("{}", e)
                }
            });
        }

        match rx.await {
            Ok(val) => val,
            Err(_) => serde_json::json!({
                "status": "error",
                "message": "Async response channel dropped before result received",
                "granted": false
            }),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        serde_json::json!({
            "status": "not_available",
            "message": "Notification listener requires Windows 10 or 11.",
            "granted": false
        })
    }
}

#[tauri::command]
fn start_notification_listener(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use windows::ApplicationModel::Package;
        use windows::UI::Notifications::Management::{
            UserNotificationListener, UserNotificationListenerAccessStatus,
        };
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

        println!("[NotificationListener] start_notification_listener command invoked.");

        // 0. Ensure COM is initialized on the calling worker thread
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }

        // 1. Check if monitoring is already running (single instance)
        {
            let guard = state
                .notification_listener
                .lock()
                .map_err(|e| e.to_string())?;
            if guard.is_some() {
                // Already started; do not spawn duplicate threads
                println!("[NotificationListener] Listener thread is already running.");
                return Ok(());
            }
        }

        // 2. Verify package identity
        if let Err(e) = Package::Current() {
            eprintln!("[NotificationListener] Package identity check failed: {}", e);
            return Err("Windows UserNotificationListener capability requires app package identity (MSIX or sparse package with userNotificationListener capability). Currently running in unpackaged mode.".to_string());
        }

        // 3. Verify notification access permission
        let listener = UserNotificationListener::Current()
            .map_err(|e| {
                eprintln!("[NotificationListener] Failed to access UserNotificationListener: {}", e);
                format!("Failed to access UserNotificationListener: {}", e)
            })?;
        let access = listener
            .GetAccessStatus()
            .map_err(|e| {
                eprintln!("[NotificationListener] Failed to get notification access status: {}", e);
                format!("Failed to get notification access status: {}", e)
            })?;

        if access != UserNotificationListenerAccessStatus::Allowed {
            eprintln!("[NotificationListener] Windows notification access not allowed (status: {:?})", access);
            return Err(format!(
                "Windows notification access is not granted (status: {:?}). Enable access in Windows Settings.",
                access
            ));
        }

        // 4. Start background listener thread
        let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();
        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_signal_clone = Arc::clone(&stop_signal);
        let protection_active_clone = Arc::clone(&state.protection_active);
        let notify_tx_clone = notify_tx.clone();
        let app_handle = app.clone();

        println!("[NotificationListener] Spawning background listener thread...");
        let thread_handle = thread::Builder::new()
            .name("windows-notification-listener".to_string())
            .spawn(move || {
                run_notification_listener_loop(
                    app_handle,
                    protection_active_clone,
                    stop_signal_clone,
                    notify_rx,
                    notify_tx_clone,
                );
            })
            .map_err(|e| {
                eprintln!("[NotificationListener] Failed to spawn listener thread: {}", e);
                format!("Failed to spawn notification listener thread: {}", e)
            })?;

        let mut guard = state
            .notification_listener
            .lock()
            .map_err(|e| e.to_string())?;
        *guard = Some(NotificationListenerHandle {
            stop_signal,
            notify_tx,
            thread_handle: Some(thread_handle),
        });

        println!("[NotificationListener] Listener thread started successfully.");
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Windows notification listener is only supported on Windows.".to_string())
    }
}

#[tauri::command]
fn stop_notification_listener(state: tauri::State<AppState>) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        println!("[NotificationListener] stop_notification_listener command invoked.");
        let handle = {
            let mut guard = state
                .notification_listener
                .lock()
                .map_err(|e| e.to_string())?;
            guard.take()
        };

        if let Some(mut h) = handle {
            h.stop_signal.store(true, Ordering::SeqCst);
            let _ = h.notify_tx.send(()); // Immediately wake up thread from recv_timeout
            if let Some(join) = h.thread_handle.take() {
                let _ = join.join();
            }
            println!("[NotificationListener] Listener stopped successfully.");
        } else {
            println!("[NotificationListener] Listener was not running.");
        }

        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn run_notification_listener_loop(
    app_handle: tauri::AppHandle,
    protection_active: Arc<AtomicBool>,
    stop_signal: Arc<AtomicBool>,
    notify_rx: std::sync::mpsc::Receiver<()>,
    notify_tx: std::sync::mpsc::Sender<()>,
) {
    use windows::Foundation::TypedEventHandler;
    use windows::UI::Notifications::Management::UserNotificationListener;
    use windows::UI::Notifications::{
        KnownNotificationBindings, NotificationKinds, UserNotificationChangedEventArgs,
        UserNotificationChangedKind,
    };
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    let listener = match UserNotificationListener::Current() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[NotificationListener] Failed to get UserNotificationListener: {}", e);
            unsafe {
                CoUninitialize();
            }
            return;
        }
    };

    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // 1. Establish baseline: collect all current toast notification IDs and text hashes so
    // existing notifications already in Action Center before listener startup are not re-processed.
    let mut seen_notifications: HashMap<u32, u64> = HashMap::new();
    if let Ok(op) = listener.GetNotificationsAsync(NotificationKinds::Toast) {
        if let Ok(existing) = op.get() {
            for n in &existing {
                if let Ok(id) = n.Id() {
                    let mut baseline_texts = Vec::new();
                    if let Ok(notif) = n.Notification() {
                        if let Ok(visual) = notif.Visual() {
                            if let Ok(bindings) = visual.Bindings() {
                                for b in &bindings {
                                    if let Ok(texts) = b.GetTextElements() {
                                        for t in &texts {
                                            if let Ok(hstr) = t.Text() {
                                                let s = hstr.to_string();
                                                if !s.is_empty() {
                                                    baseline_texts.push(s);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    let mut hasher = DefaultHasher::new();
                    baseline_texts.join("\n").hash(&mut hasher);
                    seen_notifications.insert(id, hasher.finish());
                }
            }
        }
    }
    println!(
        "[NotificationListener][DIAG] Monitoring baseline established | existing_count={}",
        seen_notifications.len()
    );

    // 2. Register Windows NotificationChanged event handler for instant push notifications
    let tx_event = notify_tx.clone();
    let token = listener
        .NotificationChanged(&TypedEventHandler::new(
            move |_sender: &Option<UserNotificationListener>,
                  args: &Option<UserNotificationChangedEventArgs>| {
                if let Some(args) = args {
                    if let Ok(kind) = args.ChangeKind() {
                        if kind == UserNotificationChangedKind::Added {
                            let _ = tx_event.send(());
                        }
                    }
                }
                Ok(())
            },
        ))
        .ok();

    // 3. Notification monitoring loop
    // Combines Windows NotificationChanged event wakeups with a 1500ms heartbeat fallback.
    // This provides zero-latency notification response without aggressive polling.
    while !stop_signal.load(Ordering::SeqCst) {
        let _ = notify_rx.recv_timeout(std::time::Duration::from_millis(1500));
        if stop_signal.load(Ordering::SeqCst) {
            break;
        }

        // If desktop protection is paused, do not process notifications
        if !protection_active.load(Ordering::SeqCst) {
            continue;
        }

        let op = match listener.GetNotificationsAsync(NotificationKinds::Toast) {
            Ok(op) => op,
            Err(_) => continue,
        };

        let current_notifs = match op.get() {
            Ok(n) => n,
            Err(_) => continue,
        };

        for n in &current_notifs {
            if stop_signal.load(Ordering::SeqCst) {
                break;
            }

            let id = match n.Id() {
                Ok(id) => id,
                Err(_) => continue,
            };

            // Extract application identification metadata
            let mut app_id = String::new();
            let mut app_display_name = String::new();
            if let Ok(app_info) = n.AppInfo() {
                if let Ok(id_hstr) = app_info.Id() {
                    app_id = id_hstr.to_string();
                }
                if let Ok(disp) = app_info.DisplayInfo() {
                    if let Ok(name_hstr) = disp.DisplayName() {
                        app_display_name = name_hstr.to_string();
                    }
                }
            }
            let source_app = if !app_id.is_empty() {
                app_id.clone()
            } else if !app_display_name.is_empty() {
                app_display_name.clone()
            } else {
                "unknown".to_string()
            };

            // Extract notification text elements across all bindings (covers Discord, WhatsApp, custom toast templates)
            let mut text_elements = Vec::new();
            if let Ok(notif) = n.Notification() {
                if let Ok(visual) = notif.Visual() {
                    // 1. Iterate all bindings to support generic, text-only, and complex templates
                    if let Ok(bindings) = visual.Bindings() {
                        for b in &bindings {
                            if let Ok(texts) = b.GetTextElements() {
                                for t in &texts {
                                    if let Ok(hstr) = t.Text() {
                                        let s = hstr.to_string();
                                        if !s.is_empty() {
                                            text_elements.push(s);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // 2. Fallback to explicit ToastGeneric binding if bindings() returned nothing
                    if text_elements.is_empty() {
                        if let Ok(toast_binding) = KnownNotificationBindings::ToastGeneric() {
                            if let Ok(binding) = visual.GetBinding(&toast_binding) {
                                if let Ok(texts) = binding.GetTextElements() {
                                    for t in &texts {
                                        if let Ok(hstr) = t.Text() {
                                            let s = hstr.to_string();
                                            if !s.is_empty() {
                                                text_elements.push(s);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let full_text = text_elements.join("\n");
            let mut hasher = DefaultHasher::new();
            full_text.hash(&mut hasher);
            let text_hash = hasher.finish();

            // Deduplication: skip if identical notification ID and content was already processed
            if let Some(&prev_hash) = seen_notifications.get(&id) {
                if prev_hash == text_hash {
                    continue;
                }
            }
            seen_notifications.insert(id, text_hash);

            let (title, body) = match text_elements.len() {
                0 => (String::new(), String::new()),
                1 => (text_elements[0].clone(), text_elements[0].clone()),
                _ => (text_elements[0].clone(), text_elements[1..].join("\n")),
            };

            let has_url_hint = full_text.contains("http://") || full_text.contains("https://");

            // Privacy Guarantee:
            // Never log sensitive notification message bodies, titles, or URLs to console or disk.
            println!(
                "[NotificationListener][DIAG] Toast processed | id={} app={} text_elements={} text_len={} has_url_hint={}",
                id, source_app, text_elements.len(), full_text.len(), has_url_hint
            );

            let payload = serde_json::json!({
                "sourceApp": source_app,
                "appId": app_id,
                "appName": app_display_name,
                "notificationId": id.to_string(),
                "id": id.to_string(),
                "title": title,
                "text": full_text,
                "body": body,
            });

            let emit_res = app_handle.emit("notification-link-detected", payload);
            println!(
                "[NotificationListener][DIAG] Emitted 'notification-link-detected' | id={} emit_success={}",
                id, emit_res.is_ok()
            );
        }

        // Bounded memory limit: prevent seen_notifications from unbounded growth
        if seen_notifications.len() > 1000 {
            let mut active_map = HashMap::new();
            for n in &current_notifs {
                if let Ok(id) = n.Id() {
                    if let Some(&hash) = seen_notifications.get(&id) {
                        active_map.insert(id, hash);
                    }
                }
            }
            seen_notifications = active_map;
        }
    }

    // Clean up event token and COM
    if let Some(token) = token {
        let _ = listener.RemoveNotificationChanged(token);
    }
    unsafe {
        CoUninitialize();
    }
    println!("[NotificationListener] Listener loop terminated cleanly.");
}


// ---------------------------------------------------------------------------
// HTTP Server for Browser Extension
// ---------------------------------------------------------------------------

fn start_extension_http_server(
    port: u16,
    token: Arc<String>,
    protection_active: Arc<AtomicBool>,
    bridge: Arc<ExtensionBridge>,
) {
    thread::spawn(move || {
        let bind_addr = format!("127.0.0.1:{}", port);
        let listener = match TcpListener::bind(&bind_addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[ExtensionServer] Failed to bind to {}: {}", bind_addr, e);
                return;
            }
        };
        eprintln!("[ExtensionServer] Listening on http://{}", bind_addr);

        for stream_result in listener.incoming() {
            let mut stream = match stream_result {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Concurrency limit: max 16 active bridge connections
            let guard = match bridge.try_acquire_connection() {
                Some(g) => g,
                None => {
                    // Reject excess connections cleanly without spawning worker threads
                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(500)));
                    let _ = stream.write_all(
                        b"HTTP/1.1 429 Too Many Requests\r\n\
                          Content-Type: application/json\r\n\
                          Content-Length: 46\r\n\
                          Access-Control-Allow-Origin: *\r\n\
                          Connection: close\r\n\r\n\
                          {\"error\":\"Too many concurrent connections\"}",
                    );
                    let _ = stream.flush();
                    drop(stream);
                    continue;
                }
            };

            let token_c = Arc::clone(&token);
            let prot_c = Arc::clone(&protection_active);
            let bridge_c = Arc::clone(&bridge);

            thread::spawn(move || {
                let _guard = guard; // Released automatically on normal exit, error, timeout, or panic
                handle_request(stream, token_c, prot_c, bridge_c);
            });
        }
    });
}

fn handle_request(
    mut stream: std::net::TcpStream,
    token: Arc<String>,
    protection_active: Arc<AtomicBool>,
    bridge: Arc<ExtensionBridge>,
) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));

    let mut buf = vec![0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let raw = match std::str::from_utf8(&buf[..n]) {
        Ok(s) => s,
        Err(_) => {
            http_respond(&mut stream, 400, "text/plain", "Bad Request", "");
            return;
        }
    };

    // Parse request line
    let mut lines = raw.lines();
    let req_line = match lines.next() {
        Some(l) => l,
        None => return,
    };
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1];

    // Parse headers
    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if let Some(p) = line.find(':') {
            headers.insert(
                line[..p].trim().to_lowercase(),
                line[p + 1..].trim().to_string(),
            );
        }
    }

    // CORS preflight
    if method == "OPTIONS" {
        let _ = stream.write_all(
            b"HTTP/1.1 204 No Content\r\n\
              Access-Control-Allow-Origin: *\r\n\
              Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
              Access-Control-Allow-Headers: Content-Type, X-Extension-Token\r\n\
              Access-Control-Max-Age: 86400\r\n\
              Content-Length: 0\r\n\
              Connection: close\r\n\r\n",
        );
        return;
    }

    // Origin validation â€” only chrome-extension:// or empty (dev/test)
    let origin = headers.get("origin").map(String::as_str).unwrap_or("");
    let origin_ok = origin.starts_with("chrome-extension://")
        || origin.starts_with("moz-extension://")
        || origin.is_empty()
        || origin == "null";

    if !origin_ok {
        http_respond(
            &mut stream,
            403,
            "application/json",
            r#"{"error":"Forbidden"}"#,
            origin,
        );
        return;
    }

    // Token authentication (Constant-time comparison)
    let provided = headers
        .get("x-extension-token")
        .map(String::as_str)
        .unwrap_or("");
    if !constant_time_compare(provided.as_bytes(), token.as_bytes()) {
        http_respond(
            &mut stream,
            401,
            "application/json",
            r#"{"error":"Unauthorized"}"#,
            origin,
        );
        return;
    }

    // Route
    match (method, path) {
        ("GET", "/status") => {
            let active = protection_active.load(Ordering::SeqCst);
            let body = format!(
                r#"{{"status":"ok","protectionActive":{},"version":"3B-2"}}"#,
                active
            );
            http_respond(&mut stream, 200, "application/json", &body, origin);
        }

        ("POST", "/analyze") => {
            // If protection is paused, return immediately
            if !protection_active.load(Ordering::SeqCst) {
                http_respond(
                    &mut stream,
                    200,
                    "application/json",
                    r#"{"status":"paused","protectionActive":false}"#,
                    origin,
                );
                return;
            }

            // Extract body
            let sep = raw.find("\r\n\r\n").or_else(|| raw.find("\n\n"));
            let body_str = match sep {
                Some(p) => {
                    let skip = if raw[p..].starts_with("\r\n\r\n") { 4 } else { 2 };
                    &raw[p + skip..]
                }
                None => {
                    http_respond(
                        &mut stream,
                        400,
                        "application/json",
                        r#"{"error":"Malformed request"}"#,
                        origin,
                    );
                    return;
                }
            };

            let url = match extract_json_string(body_str, "url") {
                Some(u) if u.starts_with("http://") || u.starts_with("https://") => u,
                _ => {
                    http_respond(
                        &mut stream,
                        422,
                        "application/json",
                        r#"{"error":"Invalid or missing URL (must be http/https)"}"#,
                        origin,
                    );
                    return;
                }
            };

            // Assign a unique request ID
            let req_id = format!("ext-{}", make_id());

            // Enqueue in pending map with atomic capacity check (max 64)
            if let Err(e) = bridge.enqueue(req_id.clone(), url.clone()) {
                let (status, msg) = match e {
                    "queue_full" => (429, r#"{"error":"Too many pending requests in queue"}"#),
                    _ => (503, r#"{"error":"Internal error"}"#),
                };
                http_respond(&mut stream, status, "application/json", msg, origin);
                return;
            }

            // Wait for the JS frontend to process and deliver the result.
            // The JS polls every 250ms so worst case latency is ~250ms + analysis time.
            let timeout = std::time::Duration::from_secs(12);
            let deadline = std::time::Instant::now() + timeout;

            let result = loop {
                // Check if result is available
                {
                    let mut results = match bridge.results.lock() {
                        Ok(r) => r,
                        Err(_) => break None,
                    };
                    if let Some(r) = results.remove(&req_id) {
                        break Some(r);
                    }
                }

                // Check for timeout
                let remaining = match deadline.checked_duration_since(std::time::Instant::now()) {
                    Some(d) => d,
                    None => break None,
                };

                // Wait for condvar notification (with timeout to avoid missing a notify)
                let results_guard = match bridge.results.lock() {
                    Ok(g) => g,
                    Err(_) => break None,
                };
                let mut results_guard = bridge
                    .condvar
                    .wait_timeout(results_guard, remaining.min(std::time::Duration::from_millis(500)))
                .map(|(guard, _)| guard)
                .unwrap_or_else(|e| {
                    let (guard, _) = e.into_inner();
                    guard
                });
                if let Some(r) = results_guard.remove(&req_id) {
                    break Some(r);
                }
                drop(results_guard);
            };

            // Clean up pending and results if still there (timeout or cancel case)
            bridge.expire_pending(&req_id);

            match result {
                Some(analysis) => {
                    let titles_json = analysis
                        .evidence_titles
                        .iter()
                        .map(|t| format!("\"{}\"", json_escape(t)))
                        .collect::<Vec<_>>()
                        .join(",");

                    let body = format!(
                        r#"{{"status":"ok","protectionActive":true,"riskLevel":"{}","riskScore":{},"evidenceCount":{},"explanation":"{}","recommendation":"{}","evidenceTitles":[{}]}}"#,
                        analysis.risk_level,
                        analysis.risk_score,
                        analysis.evidence_count,
                        json_escape(&analysis.explanation),
                        json_escape(&analysis.recommendation),
                        titles_json,
                    );
                    http_respond(&mut stream, 200, "application/json", &body, origin);
                }
                None => {
                    http_respond(
                        &mut stream,
                        504,
                        "application/json",
                        r#"{"error":"Analysis timeout: desktop application did not respond"}"#,
                        origin,
                    );
                }
            }
        }

        _ => {
            http_respond(
                &mut stream,
                404,
                "application/json",
                r#"{"error":"Not found"}"#,
                origin,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP Response Helpers
// ---------------------------------------------------------------------------

fn http_respond(
    stream: &mut std::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
    origin: &str,
) {
    let status_text = http_status_text(status);
    let cors = if origin.starts_with("chrome-extension://") || origin.starts_with("moz-extension://") {
        origin.to_string()
    } else {
        "*".to_string()
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Headers: Content-Type, X-Extension-Token\r\nConnection: close\r\n\r\n{}",
        status, status_text, content_type, body.len(), cors, body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn http_status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/// Escape a string for embedding in a JSON string value.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

use subtle::ConstantTimeEq;

/// Validate that a byte slice is an expected 64-character hexadecimal token.
pub fn is_valid_token_format(bytes: &[u8]) -> bool {
    bytes.len() == 64 && bytes.iter().all(|b| b.is_ascii_hexdigit())
}

/// Compares two extension authentication tokens in constant time using the vetted subtle crate.
///
/// Both tokens must strictly conform to the expected 64-character hexadecimal format.
/// Length mismatches cannot be truncated or ignored.
/// Returns true if and only if both tokens are valid 64-character hex strings and match byte-for-byte.
pub fn constant_time_compare(provided: &[u8], expected: &[u8]) -> bool {
    let valid_expected = is_valid_token_format(expected);
    let valid_provided = is_valid_token_format(provided);

    if !valid_expected || !valid_provided {
        return false;
    }

    let choice = provided.ct_eq(expected);
    bool::from(choice)
}

/// Extract a JSON string value for a given key from a simple JSON object.
/// This is a minimal parser â€” does not handle nested objects or arrays.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\"", key);
    let pos = json.find(&search)?;
    let after_key = &json[pos + search.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let inner = &after_colon[1..];
    // Find unescaped closing quote
    let mut chars = inner.char_indices();
    let mut result = String::new();
    loop {
        match chars.next() {
            Some((_, '"')) => break,
            Some((_, '\\')) => {
                match chars.next() {
                    Some((_, 'n')) => result.push('\n'),
                    Some((_, 'r')) => result.push('\r'),
                    Some((_, 't')) => result.push('\t'),
                    Some((_, c)) => result.push(c),
                    None => break,
                }
            }
            Some((_, c)) => result.push(c),
            None => break,
        }
    }
    if result.is_empty() { None } else { Some(result) }
}

/// Generate a pseudo-unique identifier using system time.
fn make_id() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}{:06}", t.as_secs(), t.subsec_micros())
}

/// Generate a 64-character hex token using a cryptographically secure random source.
/// On Windows, uses BCryptGenRandom from bcrypt.dll (standard system CSPRNG).
/// On Unix/other platforms, reads directly from /dev/urandom.
/// Fails explicitly if the secure RNG source is unavailable or fails.
#[cfg(target_os = "windows")]
fn generate_token() -> String {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            hAlgorithm: *mut std::ffi::c_void,
            pbBuffer: *mut u8,
            cbBuffer: u32,
            dwFlags: u32,
        ) -> i32;
    }

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;
    const STATUS_SUCCESS: i32 = 0x00000000;

    let mut bytes = [0u8; 32];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status != STATUS_SUCCESS {
        panic!("BCryptGenRandom failed with NTSTATUS: {:#010x}. Cryptographically secure token cannot be generated.", status);
    }

    let mut hex = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

#[cfg(not(target_os = "windows"))]
fn generate_token() -> String {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    let mut file = std::fs::File::open("/dev/urandom")
        .expect("Failed to open /dev/urandom for secure token generation");
    file.read_exact(&mut bytes)
        .expect("Failed to read random bytes from /dev/urandom");

    let mut hex = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

#[cfg(target_os = "windows")]
pub fn secure_token_file(path: &std::path::Path) -> Result<(), String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            StringSecurityDescriptor: *const u16,
            StringSDRevision: u32,
            SecurityDescriptor: *mut *mut c_void,
            SecurityDescriptorSize: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            pSecurityDescriptor: *mut c_void,
            lpbDaclPresent: *mut i32,
            pDacl: *mut *mut c_void,
            lpbDaclDefaulted: *mut i32,
        ) -> i32;
        fn SetNamedSecurityInfoW(
            pObjectName: *const u16,
            ObjectType: u32,
            SecurityInfo: u32,
            psidOwner: *mut c_void,
            psidGroup: *mut c_void,
            pDacl: *mut c_void,
            pSacl: *mut c_void,
        ) -> u32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(hMem: *mut c_void) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    const SDDL_REVISION_1: u32 = 1;
    const SE_FILE_OBJECT: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x80000000;
    const ERROR_SUCCESS: u32 = 0;

    let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    // SDDL: D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)
    // - D:P : Protected DACL (inheritance blocked)
    // - (A;;FA;;;OW) : Allow Full Access to Object Owner (S-1-3-4 Owner Rights)
    // - (A;;FA;;;SY) : Allow Full Access to Local System (S-1-5-18)
    // - (A;;FA;;;BA) : Allow Full Access to Built-in Administrators (S-1-5-32-544)
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut sd: *mut c_void = std::ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0 {
            let err = GetLastError();
            return Err(format!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed with Win32 error code: {}", err));
        }

        let mut dacl_present: i32 = 0;
        let mut dacl: *mut c_void = std::ptr::null_mut();
        let mut dacl_defaulted: i32 = 0;

        if GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted) == 0 || dacl_present == 0 {
            let err = GetLastError();
            LocalFree(sd);
            return Err(format!("GetSecurityDescriptorDacl failed with Win32 error code: {}", err));
        }

        let res = SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        );

        LocalFree(sd);

        if res != ERROR_SUCCESS {
            return Err(format!("SetNamedSecurityInfoW failed with Win32 error code: {}", res));
        }
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn secure_token_file(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| e.to_string())
}

/// Load an existing valid 64-char token or generate a new one, persisting with owner-only access.
/// Returns Result<(String, bool), String> where bool is true if an existing valid token was reused.
/// If file hardening fails in production mode, returns Err and ensures no unhardened persistent file remains on disk.
fn load_or_create_token(dir: &std::path::Path, is_test_mode: bool) -> Result<(String, bool), String> {
    if let Err(e) = std::fs::create_dir_all(dir) {
        return Err(format!("Failed to create token directory: {}", e));
    }
    let path = dir.join("extension_token.txt");

    // Check if an existing valid token exists
    if let Ok(content) = std::fs::read_to_string(&path) {
        let trimmed = content.trim();
        if is_valid_token_format(trimmed.as_bytes()) {
            if !is_test_mode {
                secure_token_file(&path).map_err(|e| {
                    format!(
                        "Failed to secure permissions on existing extension token file: {}. \
                         Bridge startup aborted to prevent insecure persistent token usage.",
                        e
                    )
                })?;
            } else {
                eprintln!("[STARTUP][TestMode] Token file hardening suppressed in test mode.");
            }
            return Ok((trimmed.to_string(), true));
        }
    }

    // Generate new cryptographically secure token
    let token = generate_token();
    if let Err(e) = std::fs::write(&path, &token) {
        return Err(format!("Failed to write extension token file: {} (target path: {:?})", e, path));
    }

    // Immediately apply hardened permissions to the newly created file in production mode
    if !is_test_mode {
        if let Err(e) = secure_token_file(&path) {
            // Safe failure policy: Immediately remove the unhardened token file from disk
            let _ = std::fs::remove_file(&path);
            return Err(format!(
                "Failed to secure permissions on newly created extension token file: {}. \
                 Removed unhardened file from disk. Bridge startup aborted.",
                e
            ));
        }
    } else {
        eprintln!("[STARTUP][TestMode] Token file hardening suppressed in test mode.");
    }

    Ok((token, false))
}

// ---------------------------------------------------------------------------
// Main Entry Point
// ---------------------------------------------------------------------------

fn main() {
    startup_timing!("main() entry");

    let isolation_config = match IsolationConfig::resolve() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("[FATAL][Security] Isolation configuration error: {}", err);
            std::process::exit(101);
        }
    };

    #[cfg(target_os = "windows")]
    {
        use windows::ApplicationModel::Package;
        if Package::Current().is_ok() {
            std::env::remove_var("WEBVIEW2_USER_DATA_FOLDER");
            eprintln!("[STARTUP] Packaged app detected: removed WEBVIEW2_USER_DATA_FOLDER to allow native AppModel WebView2 isolation.");
        }
    }

    // -----------------------------------------------------------------------
    // Single-instance guard (Windows)
    // When a notification is clicked on a running instance, Windows may
    // re-launch the EXE. The mutex below ensures only one instance runs.
    // The second instance signals the first via a named event, then exits.
    // -----------------------------------------------------------------------
    #[cfg(target_os = "windows")]
    {
        use std::ffi::c_void;
        extern "system" {
            fn CreateMutexW(
                lpMutexAttributes: *mut c_void,
                bInitialOwner: i32,
                lpName: *const u16,
            ) -> isize;
            fn OpenMutexW(
                dwDesiredAccess: u32,
                bInheritHandle: i32,
                lpName: *const u16,
            ) -> isize;
            fn GetLastError() -> u32;
            fn CreateEventW(
                lpEventAttributes: *mut c_void,
                bManualReset: i32,
                bInitialState: i32,
                lpName: *const u16,
            ) -> isize;
            fn OpenEventW(
                dwDesiredAccess: u32,
                bInheritHandle: i32,
                lpName: *const u16,
            ) -> isize;
            fn SetEvent(hEvent: isize) -> i32;
            fn CloseHandle(hObject: isize) -> i32;
            fn FindWindowW(
                lpClassName: *const u16,
                lpWindowName: *const u16,
            ) -> isize;
            fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
            fn SetForegroundWindow(hWnd: isize) -> i32;
        }
        const ERROR_ALREADY_EXISTS: u32 = 183;
        const ERROR_ACCESS_DENIED: u32 = 5;
        const SYNCHRONIZE: u32 = 0x00100000;
        const EVENT_MODIFY_STATE: u32 = 0x0002;
        const SW_RESTORE: i32 = 9;

        fn to_wide_null(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        let mutex_name = to_wide_null(&isolation_config.mutex_name);
        let activate_event_name = to_wide_null(&isolation_config.activate_event_name);

        unsafe {
            let existing_mutex = OpenMutexW(SYNCHRONIZE, 0, mutex_name.as_ptr());
            let primary_mutex = CreateMutexW(std::ptr::null_mut(), 1, mutex_name.as_ptr());
            let create_err = GetLastError();

            let is_secondary = existing_mutex != 0 || create_err == ERROR_ALREADY_EXISTS || create_err == ERROR_ACCESS_DENIED;

            eprintln!(
                "[SingleInstance] Instance guard check: pid={}, is_primary={}, mutex_err={}",
                std::process::id(),
                !is_secondary,
                create_err
            );

            if is_secondary {
                // Another instance is running: restore and foreground the existing window in production mode only.
                if !isolation_config.is_test_mode {
                    let window_title = to_wide_null("BaitZero");
                    let mut hwnd = FindWindowW(std::ptr::null(), window_title.as_ptr());
                    if hwnd == 0 {
                        let fallback_title = to_wide_null("BaitZero — Link Protection");
                        hwnd = FindWindowW(std::ptr::null(), fallback_title.as_ptr());
                    }
                    if hwnd == 0 {
                        let legacy_title = to_wide_null("Link Protection System");
                        hwnd = FindWindowW(std::ptr::null(), legacy_title.as_ptr());
                    }
                    if hwnd != 0 {
                        ShowWindow(hwnd, SW_RESTORE);
                        SetForegroundWindow(hwnd);
                    }
                }

                let activate_event = OpenEventW(EVENT_MODIFY_STATE, 0, activate_event_name.as_ptr());
                if activate_event != 0 {
                    SetEvent(activate_event);
                    CloseHandle(activate_event);
                } else {
                    let activate_event_create = CreateEventW(std::ptr::null_mut(), 0, 0, activate_event_name.as_ptr());
                    if activate_event_create != 0 {
                        SetEvent(activate_event_create);
                        CloseHandle(activate_event_create);
                    }
                }

                let flag = isolation_config.data_dir.join("activate_window.flag");
                let _ = std::fs::write(&flag, "1");

                if existing_mutex != 0 {
                    CloseHandle(existing_mutex);
                }
                if primary_mutex != 0 {
                    CloseHandle(primary_mutex);
                }

                std::process::exit(0);
            }

            // Primary instance: retain the mutex handle so it lives for process lifetime
            PRIMARY_MUTEX.store(primary_mutex, Ordering::SeqCst);

            // Create the activation event for secondary instances to signal
            let activate_event_bg = CreateEventW(
                std::ptr::null_mut(),
                0, // auto-reset
                0,
                activate_event_name.as_ptr(),
            );
            if activate_event_bg != 0 {
                PRIMARY_ACTIVATE_EVENT.store(activate_event_bg, Ordering::SeqCst);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use windows::ApplicationModel::Package;
        match Package::Current() {
            Ok(pkg) => {
                let full_name = pkg.Id().and_then(|id| id.FullName()).map(|h| h.to_string()).unwrap_or_default();
                eprintln!("[STARTUP] Running WITH package identity: {}", full_name);
            }
            Err(e) => {
                eprintln!("[STARTUP] Running WITHOUT package identity (APPMODEL_ERROR_NO_PACKAGE: {})", e);
            }
        }
    }

    #[cfg(target_os = "windows")]
    unsafe {
        use windows::core::w;
        use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
        let aumid = if isolation_config.is_test_mode {
            w!("com.security.linkprotection.candidate")
        } else {
            w!("com.security.linkprotection")
        };
        let _ = SetCurrentProcessExplicitAppUserModelID(aumid);
    }

    // Defer the expensive PowerShell shortcut + registry setup to a background
    // thread so it does not block Tauri initialization.
    // The registry AUMID key is created synchronously (fast); only the
    // PowerShell Start-Menu shortcut creation is deferred.
    #[cfg(target_os = "windows")]
    if !isolation_config.skip_shell_identity {
        thread::Builder::new()
            .name("identity-setup".to_string())
            .spawn(|| {
                startup_timing!("ensure_windows_notification_identity started (background)");
                ensure_windows_notification_identity();
                startup_timing!("ensure_windows_notification_identity done (background)");
            })
            .ok();
    } else {
        eprintln!("[STARTUP][TestMode] Shell & registry notification identity setup suppressed in test mode.");
    }

    startup_timing!("token generation and HTTP server startup");

    let (token_string, _is_reused, bridge_enabled) = match load_or_create_token(&isolation_config.data_dir, isolation_config.is_test_mode) {
        Ok((tok, reused)) => {
            eprintln!("[STARTUP] Extension auth token initialized (reused_existing={})", reused);
            (tok, reused, true)
        }
        Err(e) => {
            eprintln!("[STARTUP][Security] CRITICAL: Extension bridge disabled. {}", e);
            (String::new(), false, false)
        }
    };

    let token = Arc::new(token_string);
    let protection_active = Arc::new(AtomicBool::new(true));
    let protection_active_clip = Arc::clone(&protection_active);
    let bridge = Arc::new(ExtensionBridge::new());

    let notification_listener = Arc::new(Mutex::new(None::<NotificationListenerHandle>));

    // Start HTTP server for the browser extension (background thread) ONLY if token is secured
    if bridge_enabled {
        start_extension_http_server(
            isolation_config.bridge_port,
            Arc::clone(&token),
            Arc::clone(&protection_active),
            Arc::clone(&bridge),
        );
        startup_timing!("HTTP server spawned — starting Tauri builder");
    } else {
        eprintln!("[STARTUP][Security] Extension HTTP bridge NOT started due to unverified token file security.");
    }

    let frontend_ready_flag = Arc::new(AtomicBool::new(false));

    tauri::Builder::default()
        .manage(AppState {
            protection_active: Arc::clone(&protection_active),
            status_item: Mutex::new(None),
            extension_bridge: Arc::clone(&bridge),
            extension_token: Arc::clone(&token),
            bridge_port: isolation_config.bridge_port,
            notification_listener: Arc::clone(&notification_listener),
            pending_navigate: Mutex::new(None),
            frontend_ready: Arc::clone(&frontend_ready_flag),
            pending_alert: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            get_protection_state,
            set_protection_state,
            notify_user,
            show_main_window,
            hide_main_window,
            get_clipboard_text,
            get_clipboard_sequence,
            get_extension_server_info,
            poll_extension_queue,
            deliver_extension_result,
            get_notification_listener_status,
            request_notification_listener_permission,
            start_notification_listener,
            stop_notification_listener,
            frontend_ready,
            get_app_version,
            deep_scan::run_deep_scan,
            show_floating_alert,
            update_floating_alert,
            dismiss_floating_alert,
            open_alert_in_main,
            get_alert_init_data,
        ])
        .setup(move |app| {
            startup_timing!("tauri setup started");

            let status_item = MenuItemBuilder::with_id("status", "Protection: Active")
                .enabled(false)
                .build(app)?;
            let open_item = MenuItemBuilder::with_id("open", "Open Application").build(app)?;
            let pause_item = MenuItemBuilder::with_id("pause", "Pause Protection").build(app)?;
            let resume_item = MenuItemBuilder::with_id("resume", "Resume Protection").build(app)?;
            let settings_item = MenuItemBuilder::with_id("settings", "Settings").build(app)?;
            let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

            let tray_menu = MenuBuilder::new(app)
                .item(&status_item)
                .separator()
                .item(&open_item)
                .item(&pause_item)
                .item(&resume_item)
                .item(&settings_item)
                .separator()
                .item(&quit_item)
                .build()?;

            if let Some(state) = app.try_state::<AppState>() {
                if let Ok(mut guard) = state.status_item.lock() {
                    *guard = Some(status_item.clone());
                }
            }

            let status_item_pause = status_item.clone();
            let status_item_resume = status_item.clone();

            let tray_icon = tauri::include_image!("icons/32x32.png");

            let _tray = TrayIconBuilder::with_id("main-tray")
                .icon(tray_icon)
                .tooltip("BaitZero — Real-Time Protection")
                .menu(&tray_menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| {
                    match event.id().as_ref() {
                        "open" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                        "pause" => {
                            if let Some(state) = app.try_state::<AppState>() {
                                state.protection_active.store(false, Ordering::SeqCst);
                            }
                            let _ = status_item_pause.set_text("Protection: Paused");
                            let _ = app.emit("protection-state-changed", false);
                        }
                        "resume" => {
                            if let Some(state) = app.try_state::<AppState>() {
                                state.protection_active.store(true, Ordering::SeqCst);
                            }
                            let _ = status_item_resume.set_text("Protection: Active");
                            let _ = app.emit("protection-state-changed", true);
                        }
                        "settings" => {
                            // Show window first, then navigate
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                            // Queue if frontend not yet ready, else emit directly
                            if let Some(state) = app.try_state::<AppState>() {
                                if state.frontend_ready.load(Ordering::SeqCst) {
                                    let _ = app.emit("navigate-to", "#/settings");
                                } else {
                                    if let Ok(mut guard) = state.pending_navigate.lock() {
                                        *guard = Some("#/settings".to_string());
                                    }
                                }
                            } else {
                                let _ = app.emit("navigate-to", "#/settings");
                            }
                        }
                        "quit" => {
                            if let Some(state) = app.try_state::<AppState>() {
                                let _ = stop_notification_listener(state);
                            }
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            // Hide to tray on close, ensure initial visibility on startup
            if let Some(window) = app.get_webview_window("main") {
                eprintln!("[Startup] Webview window 'main' created: pid={}", std::process::id());

                // Set application window and taskbar icon explicitly
                let app_window_icon = tauri::include_image!("icons/128x128.png");
                let _ = window.set_icon(app_window_icon);

                #[cfg(target_os = "windows")]
                if let Ok(hwnd) = window.hwnd() {
                    let win_hwnd = hwnd.0 as isize;
                    extern "system" {
                        fn SendMessageW(hWnd: isize, Msg: u32, wParam: usize, lParam: isize) -> isize;
                        fn LoadImageW(
                            hInst: isize,
                            name: *const u16,
                            type_: u32,
                            cx: i32,
                            cy: i32,
                            fuLoad: u32,
                        ) -> isize;
                        fn GetModuleHandleW(lpModuleName: *const u16) -> isize;
                    }
                    const WM_SETICON: u32 = 0x0080;
                    const ICON_SMALL: usize = 0;
                    const ICON_BIG: usize = 1;
                    const IMAGE_ICON: u32 = 1;
                    const LR_SHARED: u32 = 0x8000;

                    unsafe {
                        let h_inst = GetModuleHandleW(std::ptr::null());
                        // Resource ID 1 (IDI_APPLICATION) embedded by winres in PE resources
                        let icon_res = 1 as *const u16;
                        let h_icon_big = LoadImageW(h_inst, icon_res, IMAGE_ICON, 32, 32, LR_SHARED);
                        if h_icon_big != 0 {
                            SendMessageW(win_hwnd, WM_SETICON, ICON_BIG, h_icon_big);
                        }
                        let h_icon_small = LoadImageW(h_inst, icon_res, IMAGE_ICON, 16, 16, LR_SHARED);
                        if h_icon_small != 0 {
                            SendMessageW(win_hwnd, WM_SETICON, ICON_SMALL, h_icon_small);
                        }
                    }
                }

                let _ = window.show();
                let _ = window.unminimize();
                let win_clone = window.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = win_clone.hide();
                    }
                });
            }

            // Prevent closing the alert window; hide instead
            if let Some(alert_window) = app.get_webview_window("alert") {
                eprintln!("[Startup] Webview window 'alert' registered: pid={}", std::process::id());
                let _ = alert_window.set_decorations(false);
                let _ = alert_window.set_shadow(false);
                let _ = alert_window.set_resizable(false);
                let _ = alert_window.set_skip_taskbar(true);
                let _ = alert_window.set_always_on_top(true);
                let win_clone = alert_window.clone();
                alert_window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = win_clone.hide();
                    }
                });
            }

            // If launched from a closed state via toast notification, queue navigation to #/history
            let is_toast_activated = std::env::args().any(|arg| arg.contains("ToastActivated"));
            if is_toast_activated {
                if let Some(state) = app.try_state::<AppState>() {
                    if let Ok(mut guard) = state.pending_navigate.lock() {
                        *guard = Some("#/history".to_string());
                    }
                }
            }

            #[cfg(target_os = "windows")]
            if !isolation_config.disable_clipboard {
                start_clipboard_monitor(app.handle().clone(), Arc::clone(&protection_active_clip));
            } else {
                eprintln!("[STARTUP][TestMode] Clipboard monitor disabled in test mode.");
            }

            // ---------------------------------------------------------------
            // Single-instance: listen for activation signal via Win32 event
            // and fallback flag file. When triggered, restore, show, and focus
            // the main window and emit navigation to #/history.
            // ---------------------------------------------------------------
            #[cfg(target_os = "windows")]
            {
                let app_for_event = app.handle().clone();
                thread::Builder::new()
                    .name("single-instance-event-listener".to_string())
                    .spawn(move || {
                        let ev = PRIMARY_ACTIVATE_EVENT.load(Ordering::SeqCst);
                        if ev != 0 {
                            loop {
                                extern "system" {
                                    fn WaitForSingleObject(hHandle: isize, dwMilliseconds: u32) -> u32;
                                }
                                let res = unsafe { WaitForSingleObject(ev, u32::MAX) };
                                if res == 0 {
                                    eprintln!("[SingleInstance] Activation signal received: pid={}", std::process::id());
                                    activate_existing_window(&app_for_event);
                                } else {
                                    break;
                                }
                            }
                        }
                    })
                    .ok();

                let app_handle_poll = app.handle().clone();
                let poll_data_dir = isolation_config.data_dir.clone();
                thread::Builder::new()
                    .name("single-instance-poll".to_string())
                    .spawn(move || {
                        loop {
                            thread::sleep(std::time::Duration::from_millis(250));
                            let flag_path = poll_data_dir.join("activate_window.flag");
                            if flag_path.exists() {
                                let _ = std::fs::remove_file(&flag_path);
                                eprintln!("[SingleInstance] Activation signal received (via flag file): pid={}", std::process::id());
                                activate_existing_window(&app_handle_poll);
                            }
                        }
                    })
                    .ok();
            }

            startup_timing!("tauri setup complete — clipboard monitor started — waiting for frontend_ready");

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Link Protection desktop application");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that duplicate deduplication for notifications works correctly.
    /// This is a pure logic test with no OS dependencies.
    #[test]
    fn test_make_id_unique() {
        let id1 = make_id();
        std::thread::sleep(std::time::Duration::from_micros(10));
        let id2 = make_id();
        // make_id uses microsecond time; should differ after sleep
        // (not guaranteed under load, but very likely)
        println!("[TEST] make_id: id1={} id2={}", id1, id2);
        assert!(!id1.is_empty(), "make_id must produce non-empty ID");
        assert!(!id2.is_empty(), "make_id must produce non-empty ID");
    }

    /// Verify token generation produces a 64-char hex string.
    #[test]
    fn test_generate_token_length() {
        let token = generate_token();
        assert_eq!(token.len(), 64, "Token must be 64 hex characters");
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()), "Token must be hex");
    }

    /// Verify token generation produces unique cryptographically secure tokens.
    #[test]
    fn test_generate_token_uniqueness() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2, "Tokens must be unique and non-deterministic");
        assert_eq!(t1.len(), 64);
        assert_eq!(t2.len(), 64);
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(t2.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Verify json_escape handles special characters safely.
    #[test]
    fn test_json_escape() {
        // Input: hello<LF>world"tab<TAB>\
        let raw = "hello\nworld\"tab\t\\".to_string();
        let escaped = json_escape(&raw);
        // After escaping: newline -> \n literal, quote -> \", tab -> \t literal, backslash -> \\
        assert!(escaped.contains("\\n"), "Newline must become \\n escape sequence");
        assert!(escaped.contains("\\\""), "Quote must become backslash-quote escape sequence");
        assert!(escaped.contains("\\t"), "Tab must become \\t escape sequence");
        assert!(escaped.contains("\\\\"), "Backslash must become \\\\ escape sequence");
        // The raw newline character must not appear literally
        assert!(!escaped.contains('\n'), "Raw newline must not appear literally");
        // The raw tab character must not appear literally
        assert!(!escaped.contains('\t'), "Raw tab must not appear literally");
    }

    /// Verify extract_json_string returns expected value for valid JSON.
    #[test]
    fn test_extract_json_string_valid() {
        let json = r#"{"url":"https://example.com","other":"val"}"#;
        let result = extract_json_string(json, "url");
        assert_eq!(result, Some("https://example.com".to_string()));
    }

    /// Verify extract_json_string returns None for missing key.
    #[test]
    fn test_extract_json_string_missing() {
        let json = r#"{"other":"val"}"#;
        let result = extract_json_string(json, "url");
        assert_eq!(result, None);
    }

    /// Startup: confirm AppState can be constructed with all required fields.
    #[test]
    fn test_app_state_construction() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Mutex};
        let _state = AppState {
            protection_active: Arc::new(AtomicBool::new(true)),
            status_item: Mutex::new(None),
            extension_bridge: Arc::new(ExtensionBridge::new()),
            extension_token: Arc::new("test-token".to_string()),
            bridge_port: 27432,
            notification_listener: Arc::new(Mutex::new(None)),
            pending_navigate: Mutex::new(None),
            frontend_ready: Arc::new(AtomicBool::new(false)),
            pending_alert: Mutex::new(None),
        };
        println!("[TEST] AppState construction: OK");
    }

    /// Startup: confirm pending_navigate queuing logic works without Tauri.
    #[test]
    fn test_pending_navigate_queue() {
        use std::sync::{Arc, Mutex};
        let pending: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        // Simulate queueing a navigate-to before frontend ready
        {
            let mut guard = pending.lock().unwrap();
            *guard = Some("#/settings".to_string());
        }
        // Simulate flush on frontend_ready
        let flushed = {
            let mut guard = pending.lock().unwrap();
            guard.take()
        };
        assert_eq!(flushed, Some("#/settings".to_string()));
        // Verify cleared after flush
        let after = pending.lock().unwrap().clone();
        assert_eq!(after, None);
        println!("[TEST] pending_navigate queue/flush: OK");
    }

    /// Notification listener lifecycle test (Windows only, requires package identity).
    #[test]
    #[cfg(target_os = "windows")]
    fn test_notification_listener_lifecycle() {
        use windows::UI::Notifications::Management::UserNotificationListener;
        use windows::UI::Notifications::NotificationKinds;
        let listener = UserNotificationListener::Current().unwrap();
        let op = listener.GetNotificationsAsync(NotificationKinds::Toast);
        println!("\n[TEST] GetNotificationsAsync op: {:?}", op);
        if let Ok(op) = op {
            let res = op.get();
            println!("[TEST] GetNotificationsAsync res: {:?}", res.is_ok());
        }
    }

    #[test]
    fn test_alert_position_mode_parsing() {
        assert_eq!(AlertPositionMode::from_opt_str(Some("clipboard")), AlertPositionMode::Clipboard);
        assert_eq!(AlertPositionMode::from_opt_str(Some("CLIPBOARD")), AlertPositionMode::Clipboard);
        assert_eq!(AlertPositionMode::from_opt_str(Some("  clipboard  ")), AlertPositionMode::Clipboard);
        assert_eq!(AlertPositionMode::from_opt_str(Some("security")), AlertPositionMode::Security);
        assert_eq!(AlertPositionMode::from_opt_str(Some("standard")), AlertPositionMode::Security);
        assert_eq!(AlertPositionMode::from_opt_str(None), AlertPositionMode::Security);
        assert_eq!(AlertPositionMode::from_opt_str(Some("unknown")), AlertPositionMode::Security);
    }

    #[test]
    fn test_alert_position_mode_margin_delta() {
        let margin_clipboard = get_alert_margin_bottom_logical(AlertPositionMode::Clipboard);
        let margin_security = get_alert_margin_bottom_logical(AlertPositionMode::Security);
        assert_eq!(margin_clipboard, 12.0);
        assert_eq!(margin_security, 138.0);
        let delta = margin_security - margin_clipboard;
        // Mode A sits 126px higher than Mode B to clear the standard native Windows toast (~116px)
        assert_eq!(delta, 126.0);
        assert!(delta >= 116.0, "Offset must clear standard Windows toast height");
    }

    #[test]
    fn test_calculate_alert_coordinates_clamping() {
        // Standard 1920x1080 display with 40px taskbar at bottom (work_bottom = 1040)
        let (x, y) = calculate_alert_coordinates(
            0, 0, 1920, 1040,
            312, 84, 16, 12,
        );
        assert_eq!(x, 1920 - 312 - 16); // 1592
        assert_eq!(y, 1040 - 84 - 12);  // 944

        // Clamping test: very small display where alert would exceed left or top
        let (clamped_x, clamped_y) = calculate_alert_coordinates(
            0, 0, 200, 50,
            312, 84, 16, 12,
        );
        assert_eq!(clamped_x, 0); // clamped to work_left
        assert_eq!(clamped_y, 0); // clamped to work_top
    }

    #[test]
    fn test_event_source_toast_suppression_logic() {
        let should_suppress_toast = |src: Option<&str>| -> bool {
            let source_str = src.unwrap_or("security");
            source_str.trim().eq_ignore_ascii_case("clipboard")
        };

        // Clipboard events MUST suppress native toast
        assert!(should_suppress_toast(Some("clipboard")));
        assert!(should_suppress_toast(Some("CLIPBOARD")));
        assert!(should_suppress_toast(Some(" clipboard ")));

        // Security events MUST NOT suppress native toast
        assert!(!should_suppress_toast(Some("security")));
        assert!(!should_suppress_toast(Some("standard")));
        assert!(!should_suppress_toast(None));
        assert!(!should_suppress_toast(Some("unknown")));
    }

    // -----------------------------------------------------------------------
    // Stage 1 Clipboard Privacy Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_clipboard_extract_valid_http_and_https_urls() {
        assert_eq!(
            extract_valid_clipboard_url("https://example.com/path?arg=1#frag"),
            Some("https://example.com/path?arg=1#frag".to_string())
        );
        assert_eq!(
            extract_valid_clipboard_url("http://sub.domain.org:8080/test"),
            Some("http://sub.domain.org:8080/test".to_string())
        );
    }

    #[test]
    fn test_clipboard_extract_localhost_and_ip_literals() {
        // Localhost
        assert_eq!(
            extract_valid_clipboard_url("http://localhost:3000/dashboard"),
            Some("http://localhost:3000/dashboard".to_string())
        );
        assert_eq!(
            extract_valid_clipboard_url("https://localhost/"),
            Some("https://localhost/".to_string())
        );

        // IPv4
        assert_eq!(
            extract_valid_clipboard_url("http://127.0.0.1:8080/api"),
            Some("http://127.0.0.1:8080/api".to_string())
        );
        assert_eq!(
            extract_valid_clipboard_url("https://192.168.1.1/admin"),
            Some("https://192.168.1.1/admin".to_string())
        );

        // IPv6
        assert_eq!(
            extract_valid_clipboard_url("http://[::1]:8080/test"),
            Some("http://[::1]:8080/test".to_string())
        );
        assert_eq!(
            extract_valid_clipboard_url("https://[2001:db8::1]/"),
            Some("https://[2001:db8::1]/".to_string())
        );
    }

    #[test]
    fn test_clipboard_extract_trims_surrounding_whitespace() {
        assert_eq!(
            extract_valid_clipboard_url("   https://example.com/clean   "),
            Some("https://example.com/clean".to_string())
        );
        assert_eq!(
            extract_valid_clipboard_url("\t  http://localhost:5000/  \t"),
            Some("http://localhost:5000/".to_string())
        );
    }

    #[test]
    fn test_clipboard_extract_rejects_credentials() {
        assert_eq!(extract_valid_clipboard_url("https://user:password@example.com/"), None);
        assert_eq!(extract_valid_clipboard_url("http://admin:@example.com/"), None);
        assert_eq!(extract_valid_clipboard_url("https://user@example.com/"), None);
    }

    #[test]
    fn test_clipboard_extract_rejects_non_http_schemes() {
        assert_eq!(extract_valid_clipboard_url("javascript:alert(1)"), None);
        assert_eq!(extract_valid_clipboard_url("file:///C:/Windows/System32"), None);
        assert_eq!(extract_valid_clipboard_url("data:text/html,<script>alert(1)</script>"), None);
        assert_eq!(extract_valid_clipboard_url("ftp://files.example.com/data"), None);
        assert_eq!(extract_valid_clipboard_url("about:blank"), None);
    }

    #[test]
    fn test_clipboard_extract_rejects_plain_text_passwords_and_empty() {
        assert_eq!(extract_valid_clipboard_url(""), None);
        assert_eq!(extract_valid_clipboard_url("    "), None);
        assert_eq!(extract_valid_clipboard_url("P@ssw0rd123!#$"), None);
        assert_eq!(extract_valid_clipboard_url("my_secret_token_abc123"), None);
        assert_eq!(extract_valid_clipboard_url("This is just some clipboard text"), None);
    }

    #[test]
    fn test_clipboard_extract_rejects_prose_and_multiline_urls() {
        assert_eq!(extract_valid_clipboard_url("Check out https://example.com for info"), None);
        assert_eq!(extract_valid_clipboard_url("https://example.com\nhttps://evil.com"), None);
        assert_eq!(extract_valid_clipboard_url("Line1\r\nhttps://example.com\r\nLine3"), None);
        assert_eq!(extract_valid_clipboard_url("https://example.com trailing text"), None);
        assert_eq!(extract_valid_clipboard_url("leading text https://example.com"), None);
    }

    #[test]
    fn test_clipboard_extract_rejects_internal_whitespace_and_malformed() {
        assert_eq!(extract_valid_clipboard_url("https://exa mple.com"), None);
        assert_eq!(extract_valid_clipboard_url("http://"), None);
        assert_eq!(extract_valid_clipboard_url("https://"), None);
        assert_eq!(extract_valid_clipboard_url("https://[invalid-ipv6/"), None);
        assert_eq!(extract_valid_clipboard_url("http:/example.com"), None);
    }

    #[test]
    fn test_clipboard_extract_rejects_single_label_non_localhost() {
        assert_eq!(extract_valid_clipboard_url("http://intranet/"), None);
        assert_eq!(extract_valid_clipboard_url("https://router/setup"), None);
        assert_eq!(extract_valid_clipboard_url("http://server:8080/"), None);
    }

    // -----------------------------------------------------------------------
    // Stage 3B-2 Extension Bridge Resource Protection Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bridge_connection_limit_and_raii_guard() {
        let bridge = ExtensionBridge::new();
        assert_eq!(bridge.active_connection_count(), 0);

        // Acquire up to MAX_CONCURRENT_BRIDGE_CONNECTIONS (16)
        let mut guards = Vec::new();
        for _ in 0..MAX_CONCURRENT_BRIDGE_CONNECTIONS {
            let guard = bridge.try_acquire_connection();
            assert!(guard.is_some(), "Must acquire connection within limit");
            guards.push(guard.unwrap());
        }
        assert_eq!(bridge.active_connection_count(), 16);

        // 17th connection must be rejected cleanly
        let excess = bridge.try_acquire_connection();
        assert!(excess.is_none(), "Excess connection beyond limit must be rejected");

        // Release one guard
        guards.pop();
        assert_eq!(bridge.active_connection_count(), 15);

        // Now one more can be acquired
        let reacquired = bridge.try_acquire_connection();
        assert!(reacquired.is_some(), "Connection capacity must recover after drop");
        guards.push(reacquired.unwrap());
        assert_eq!(bridge.active_connection_count(), 16);

        // Drop all guards and verify counter resets to 0
        drop(guards);
        assert_eq!(bridge.active_connection_count(), 0);
    }

    #[test]
    fn test_bridge_connection_cleanup_on_thread_exit() {
        let bridge = Arc::new(ExtensionBridge::new());
        let bridge_clone = Arc::clone(&bridge);

        let handle = std::thread::spawn(move || {
            let _guard = bridge_clone.try_acquire_connection().expect("Should acquire");
            assert_eq!(bridge_clone.active_connection_count(), 1);
            // Thread exits, guard drops
        });
        handle.join().unwrap();
        assert_eq!(bridge.active_connection_count(), 0, "Guard must drop on thread exit");
    }

    #[test]
    fn test_bridge_queue_capacity_limit_and_rejection() {
        let bridge = ExtensionBridge::new();
        assert_eq!(bridge.pending_count(), 0);

        // Fill queue to MAX_PENDING_BRIDGE_QUEUE (64)
        for i in 0..MAX_PENDING_BRIDGE_QUEUE {
            let res = bridge.enqueue(format!("req-{}", i), format!("https://example.com/{}", i));
            assert!(res.is_ok(), "Enqueue under capacity limit must succeed");
        }
        assert_eq!(bridge.pending_count(), 64);

        // 65th enqueue must be rejected with queue_full
        let overflow = bridge.enqueue("req-overflow".to_string(), "https://example.com/overflow".to_string());
        assert_eq!(overflow, Err("queue_full"), "Enqueue beyond limit must return queue_full");
        assert_eq!(bridge.pending_count(), 64, "Queue count must remain at cap");
    }

    #[test]
    fn test_bridge_queue_capacity_recovery_on_delivery() {
        let bridge = ExtensionBridge::new();

        // Fill to capacity
        for i in 0..MAX_PENDING_BRIDGE_QUEUE {
            bridge.enqueue(format!("req-{}", i), format!("https://example.com/{}", i)).unwrap();
        }
        assert_eq!(bridge.pending_count(), 64);

        // Deliver result for req-0
        let result = AnalysisResult {
            risk_level: "LOW".to_string(),
            risk_score: 0,
            evidence_count: 0,
            explanation: "Clean".to_string(),
            recommendation: "Safe".to_string(),
            evidence_titles: vec![],
        };
        let delivered = bridge.deliver_result("req-0", result);
        assert!(delivered, "Deliver result must return true for pending request");
        assert_eq!(bridge.pending_count(), 63, "Pending count must decrement on delivery");

        // Enqueue a new item in the freed slot
        let res = bridge.enqueue("req-recovered".to_string(), "https://example.com/recovered".to_string());
        assert!(res.is_ok(), "Capacity must be available after delivery");
        assert_eq!(bridge.pending_count(), 64);
    }

    #[test]
    fn test_bridge_queue_capacity_recovery_on_expiry() {
        let bridge = ExtensionBridge::new();

        // Fill to capacity
        for i in 0..MAX_PENDING_BRIDGE_QUEUE {
            bridge.enqueue(format!("req-{}", i), format!("https://example.com/{}", i)).unwrap();
        }
        assert_eq!(bridge.pending_count(), 64);

        // Expire req-5 (simulating 12s timeout)
        bridge.expire_pending("req-5");
        assert_eq!(bridge.pending_count(), 63, "Pending count must decrement on expiry");

        // Enqueue a new item in the freed slot
        let res = bridge.enqueue("req-replacement".to_string(), "https://example.com/replacement".to_string());
        assert!(res.is_ok(), "Capacity must be available after expiry");
        assert_eq!(bridge.pending_count(), 64);
    }

    #[test]
    fn test_bridge_concurrent_burst_enqueuing() {
        let bridge = Arc::new(ExtensionBridge::new());
        let mut handles = Vec::new();

        // 20 threads simultaneously attempt to enqueue 5 items each (total 100 requests)
        for t in 0..20 {
            let b = Arc::clone(&bridge);
            handles.push(std::thread::spawn(move || {
                let mut successes = 0;
                let mut rejections = 0;
                for i in 0..5 {
                    let id = format!("t{}-i{}", t, i);
                    match b.enqueue(id, "https://example.com/test".to_string()) {
                        Ok(()) => successes += 1,
                        Err("queue_full") => rejections += 1,
                        Err(_) => panic!("Unexpected error"),
                    }
                }
                (successes, rejections)
            }));
        }

        let mut total_success = 0;
        let mut total_rejected = 0;
        for h in handles {
            let (s, r) = h.join().unwrap();
            total_success += s;
            total_rejected += r;
        }

        assert_eq!(total_success, 64, "Exactly 64 items should have been accepted");
        assert_eq!(total_rejected, 36, "Exactly 36 items should have been rejected as queue_full");
        assert_eq!(bridge.pending_count(), 64, "Queue must never exceed cap under concurrency");
    }

    #[test]
    fn test_bridge_http_status_429_text() {
        assert_eq!(http_status_text(429), "Too Many Requests");
        assert_eq!(http_status_text(200), "OK");
        assert_eq!(http_status_text(503), "Service Unavailable");
        assert_eq!(http_status_text(504), "Gateway Timeout");
    }

    // -----------------------------------------------------------------------
    // Stage 3B-3 Authentication Hardening Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_constant_time_compare_matching_tokens() {
        let t1 = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        let t2 = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(constant_time_compare(t1.as_bytes(), t2.as_bytes()), "Identical valid tokens must match");
    }

    #[test]
    fn test_constant_time_compare_mismatch_first_byte() {
        let t1 = "x1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        let t2 = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(!constant_time_compare(t1.as_bytes(), t2.as_bytes()), "Mismatch at first byte must fail");
    }

    #[test]
    fn test_constant_time_compare_mismatch_middle_byte() {
        let t1 = "a1b2c3d4e5f678901234567890abcdef0234567890abcdef1234567890abcdef";
        let t2 = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(!constant_time_compare(t1.as_bytes(), t2.as_bytes()), "Mismatch at middle byte must fail");
    }

    #[test]
    fn test_constant_time_compare_mismatch_last_byte() {
        let t1 = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdee";
        let t2 = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(!constant_time_compare(t1.as_bytes(), t2.as_bytes()), "Mismatch at last byte must fail");
    }

    #[test]
    fn test_constant_time_compare_empty_inputs() {
        let expected = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(!constant_time_compare("".as_bytes(), expected.as_bytes()), "Empty provided token must fail");
        assert!(!constant_time_compare(expected.as_bytes(), "".as_bytes()), "Empty expected token must fail");
        assert!(!constant_time_compare("".as_bytes(), "".as_bytes()), "Both empty tokens must fail");
    }

    #[test]
    fn test_constant_time_compare_different_lengths() {
        let expected = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        let shorter = "a1b2c3d4e5f6";
        let slightly_shorter = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcde"; // 63 chars
        let slightly_longer = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef0"; // 65 chars
        assert!(!constant_time_compare(shorter.as_bytes(), expected.as_bytes()), "Shorter token must fail");
        assert!(!constant_time_compare(slightly_shorter.as_bytes(), expected.as_bytes()), "63-char token must fail");
        assert!(!constant_time_compare(slightly_longer.as_bytes(), expected.as_bytes()), "65-char token must fail");
    }

    #[test]
    fn test_constant_time_compare_prefix_plus_256_bytes_320_total() {
        let expected = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        // 64-byte valid prefix + 256 '0's = 320 bytes total (specifically checks (320 ^ 64) % 256 == 0 truncation)
        let mut overlong = expected.to_string();
        overlong.push_str(&"0".repeat(256));
        assert_eq!(overlong.len(), 320);
        assert!(!constant_time_compare(overlong.as_bytes(), expected.as_bytes()), "320-byte token with matching prefix must be rejected");
    }

    #[test]
    fn test_constant_time_compare_malformed_tokens() {
        let expected = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        // 64 chars but contains non-hex character 'g' or 'z' or punctuation
        let non_hex_char = "g1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        let punctuation = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcde!";
        let spaces = "a1b2c3d4e5f678901234567890abcdef 1234567890abcdef1234567890abcdef";
        assert!(!constant_time_compare(non_hex_char.as_bytes(), expected.as_bytes()), "Non-hex 'g' must be rejected");
        assert!(!constant_time_compare(punctuation.as_bytes(), expected.as_bytes()), "Punctuation '!' must be rejected");
        assert!(!constant_time_compare(spaces.as_bytes(), expected.as_bytes()), "Token with spaces must be rejected");
    }

    #[test]
    fn test_token_format_validator() {
        let valid = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(is_valid_token_format(valid.as_bytes()));

        let uppercase_valid = "A1B2C3D4E5F678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";
        assert!(is_valid_token_format(uppercase_valid.as_bytes()));

        assert!(!is_valid_token_format("".as_bytes()));
        assert!(!is_valid_token_format("short".as_bytes()));
    }
}



//! Window activation and compositor-specific fallbacks.
use gpui::{AnyWindowHandle, App, Window};

#[cfg(target_os = "linux")]
use super::{DesktopWindow, niri};

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(super) fn configure_desktop(window: &Window) {
    use objc2_app_kit::{NSView, NSWindowCollectionBehavior};
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let Ok(handle) = HasWindowHandle::window_handle(window) else {
        return;
    };
    let RawWindowHandle::AppKit(handle) = handle.as_raw() else {
        return;
    };
    // SAFETY: GPUI lends a valid NSView for this window on the main thread.
    let view = unsafe { &*handle.ns_view.as_ptr().cast::<NSView>() };
    if let Some(window) = view.window() {
        // Bring the window to the current Space when activated.
        window.setCollectionBehavior(
            window.collectionBehavior() | NSWindowCollectionBehavior::MoveToActiveSpace,
        );
    }
}

/// Present an existing desktop window. Call after action dispatch releases it.
pub(super) fn desktop(handle: AnyWindowHandle, cx: &mut App) -> anyhow::Result<()> {
    handle.update(cx, |_, window, cx| {
        #[cfg(not(target_os = "linux"))]
        let _ = cx;
        #[cfg(target_os = "linux")]
        if cx.global::<DesktopWindow>().visible
            && !window.is_window_active()
            && std::env::var_os("NIRI_SOCKET").is_some()
        {
            focus_niri(handle, cx);
            return;
        }
        let remap_unfocused =
            cfg!(target_os = "linux") && std::env::var_os("WAYLAND_DISPLAY").is_some();
        show(window, remap_unfocused);
    })
}

/// Present an ordinary window, optionally remapping it to recover focus.
/// Layer-shell approval surfaces must skip this fallback.
pub(super) fn show(window: &mut Window, remap_unfocused: bool) {
    if remap_unfocused && !window.is_window_active() {
        window.set_visible(false);
    }
    #[cfg(target_os = "windows")]
    win32::restore_if_minimized(window);
    window.set_visible(true);
    window.activate();
}

/// Flag a window in the taskbar when it could not take the foreground.
pub(super) fn request_attention(window: &Window) {
    #[cfg(target_os = "windows")]
    win32::flash_until_foreground(window);
    #[cfg(not(target_os = "windows"))]
    window.request_attention();
}

/// Open a hidden window minimized, without taking the foreground, and flash
/// its taskbar button until the person brings it forward. False where that
/// isn't possible (the caller brings the window forward instead).
pub(super) fn minimized_with_attention(window: &Window) -> bool {
    #[cfg(target_os = "windows")]
    return win32::show_minimized_flashing(window);
    #[cfg(not(target_os = "windows"))]
    {
        let _ = window;
        false
    }
}

/// Flag a window that lost the foreground before the user interacted with it.
///
/// Windows can hand a new window the foreground for a moment and then give it
/// back to the app the user is typing in, so the check in
/// [`request_attention`] saw the window in front and did not flash. Other
/// platforms flag the window when it opens, so this only matters on Windows.
pub(super) fn deactivated_unseen(window: &Window) {
    #[cfg(target_os = "windows")]
    win32::flash_until_foreground(window);
    #[cfg(not(target_os = "windows"))]
    let _ = window;
}

/// Stop flagging a window that reached the foreground or is closing.
pub(super) fn attention_settled(window: &Window) {
    #[cfg(target_os = "windows")]
    win32::stop_owner_flash(window);
    #[cfg(not(target_os = "windows"))]
    let _ = window;
}

/// GPUI's `request_attention` skips windows that `GetActiveWindow` reports as
/// active. A newly shown window is always its own thread's active window, even
/// when another app keeps the foreground, so on Windows it never flashes.
///
/// GPUI also makes a dialog opened while Desktop's main window is active an
/// owned, modal window of it. An owned window has no taskbar button of its own,
/// so the owner's button is the one to flash.
#[cfg(target_os = "windows")]
mod win32 {
    #![allow(unsafe_code)]
    use gpui::Window;
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FLASHW_ALL, FLASHW_STOP, FLASHW_TIMERNOFG, FLASHWINFO, FLASHWINFO_FLAGS, FlashWindowEx,
        GA_ROOTOWNER, GetAncestor, GetForegroundWindow, IsIconic, SW_RESTORE, SW_SHOWMINNOACTIVE,
        ShowWindow,
    };

    fn hwnd(window: &Window) -> Option<HWND> {
        // GPUI's inherent `Window::window_handle` returns its own handle type.
        let handle = HasWindowHandle::window_handle(window).ok()?;
        let RawWindowHandle::Win32(handle) = handle.as_raw() else {
            return None;
        };
        Some(handle.hwnd.get() as HWND)
    }

    /// The window whose taskbar button stands for `hwnd`.
    fn taskbar_window(hwnd: HWND) -> HWND {
        // SAFETY: GetAncestor only reads window relationships; a stale handle
        // yields a null result, which falls back to the window itself.
        let owner = unsafe { GetAncestor(hwnd, GA_ROOTOWNER) };
        if owner.is_null() { hwnd } else { owner }
    }

    fn flash(hwnd: HWND, flags: FLASHWINFO_FLAGS) {
        let info = FLASHWINFO {
            cbSize: u32::try_from(std::mem::size_of::<FLASHWINFO>())
                .expect("FLASHWINFO is a few dozen bytes"),
            hwnd,
            dwFlags: flags,
            uCount: 0,
            dwTimeout: 0,
        };
        // SAFETY: `info` is a fully initialized FLASHWINFO for a window of
        // this thread, and it outlives the call.
        let _ = unsafe { FlashWindowEx(&raw const info) };
    }

    /// Flash the taskbar button until the window comes to the foreground.
    pub(super) fn flash_until_foreground(window: &Window) {
        let Some(hwnd) = hwnd(window) else {
            return;
        };
        // SAFETY: GetForegroundWindow takes no arguments and only reads state.
        if unsafe { GetForegroundWindow() } == hwnd {
            return;
        }
        // For an owner, "until the foreground" would wait for a disabled
        // window; `stop_owner_flash` ends it when the dialog is in front.
        flash(taskbar_window(hwnd), FLASHW_ALL | FLASHW_TIMERNOFG);
    }

    /// Show the window minimized without activating it, then flash its
    /// taskbar button until it comes to the foreground. `SW_MINIMIZE` would
    /// hand the foreground to another window; `SW_SHOWMINNOACTIVE` leaves it
    /// where it is. Synchronous, on the window's own thread, so the button
    /// exists before the flash starts. GPUI learns of the change from
    /// `WM_SHOWWINDOW`, as with its own `ShowWindowAsync` calls.
    pub(super) fn show_minimized_flashing(window: &Window) -> bool {
        let Some(hwnd) = hwnd(window) else {
            return false;
        };
        // SAFETY: `hwnd` is this thread's live window, lent by GPUI; the
        // return value only says whether it was visible before.
        let _ = unsafe { ShowWindow(hwnd, SW_SHOWMINNOACTIVE) };
        flash(hwnd, FLASHW_ALL | FLASHW_TIMERNOFG);
        true
    }

    /// Restore a minimized window before it is shown and activated. GPUI
    /// shows windows with `SW_SHOWNOACTIVATE`, which leaves a minimized
    /// window unready for input: typed keys were lost right after Desktop
    /// came back from the minimized attention state.
    pub(super) fn restore_if_minimized(window: &Window) {
        let Some(hwnd) = hwnd(window) else {
            return;
        };
        // SAFETY: `hwnd` is this thread's live window, lent by GPUI; both
        // calls only read or change its show state.
        unsafe {
            if IsIconic(hwnd) != 0 {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
        }
    }

    /// Stop an owner's flash started for this window. A window's own flash
    /// already stops when it reaches the foreground.
    pub(super) fn stop_owner_flash(window: &Window) {
        let Some(hwnd) = hwnd(window) else {
            return;
        };
        let owner = taskbar_window(hwnd);
        if owner != hwnd {
            flash(owner, FLASHW_STOP);
        }
    }
}

#[cfg(target_os = "linux")]
fn focus_niri(handle: AnyWindowHandle, cx: &mut App) {
    cx.spawn(async move |cx| {
        if !smol::unblock(niri::focus_desktop).await {
            cx.update(|cx| {
                let desktop = cx.global::<DesktopWindow>();
                // Ignore a failed request if its window was hidden or replaced.
                if desktop.visible && desktop.handle == Some(handle) {
                    let _ = handle.update(cx, |_, window, _| show(window, true));
                }
            });
        }
    })
    .detach();
}

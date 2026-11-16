//! Win32 task dialogs (`TaskDialogIndirect`), which show the pages of
//! [`crate::ui`]: native, read by screen readers through UI Automation,
//! and small. This is the installer's one module allowed unsafe code, for
//! the calls into Windows; everything it shows and decides is built
//! elsewhere as plain data.
//!
//! One dialog window shows every page: a page moves to the next with
//! `TDM_NAVIGATE_PAGE`. A toggle is a command link; clicking it flips it and
//! shows the page again with the focus back on it. A page with a progress
//! bar polls the work on a timer. `TaskDialogIndirect` is looked up when it
//! is first needed, not imported: it exists only in Common Controls 6,
//! which the executable's manifest activates (`windows/`, `build.rs`), and
//! the test executables built from this crate carry no manifest.

#![allow(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::ffi::c_void;

use windows_sys::Win32::Foundation::{HWND, LPARAM, S_FALSE, S_OK, WPARAM};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows_sys::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TD_ERROR_ICON, TD_WARNING_ICON,
    TDCBF_CANCEL_BUTTON, TDCBF_CLOSE_BUTTON, TDCBF_OK_BUTTON, TDE_CONTENT,
    TDF_ALLOW_DIALOG_CANCELLATION, TDF_CALLBACK_TIMER, TDF_EXPANDED_BY_DEFAULT,
    TDF_SHOW_MARQUEE_PROGRESS_BAR, TDF_USE_COMMAND_LINKS_NO_ICON, TDM_CLICK_BUTTON,
    TDM_ENABLE_BUTTON, TDM_NAVIGATE_PAGE, TDM_SET_ELEMENT_TEXT, TDM_SET_PROGRESS_BAR_MARQUEE,
    TDN_BUTTON_CLICKED, TDN_CREATED, TDN_EXPANDO_BUTTON_CLICKED, TDN_NAVIGATED, TDN_TIMER,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    IDCANCEL, IDCLOSE, IDOK, PostMessageW, SendMessageW,
};
use windows_sys::core::{HRESULT, PCWSTR};

use crate::ui::{Buttons, Icon, Page, TITLE};

/// What the user did, or the timer of a progress page.
pub enum Event<'a> {
    /// OK, with the toggles' states.
    Ok(&'a [bool]),
    /// Cancel, Close, Escape or the window's close button, with the
    /// toggles' states.
    Cancel(&'a [bool]),
    /// A progress page's timer (about five times a second).
    Timer,
}

/// What the dialog does next.
pub enum Next {
    Stay,
    /// Replace the page's text.
    Content(String),
    /// Show another page.
    Page(Page),
    /// Close the dialog.
    Close,
}

/// The first toggle's button ID; the others follow.
const TOGGLE: i32 = 1000;

/// The dialog's width in dialog units.
const WIDTH: u32 = 300;

type TaskDialogIndirect =
    unsafe extern "system" fn(*const TASKDIALOGCONFIG, *mut i32, *mut i32, *mut i32) -> HRESULT;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A page as Windows takes it. The configuration points into the strings
/// and buttons, whose buffers stay where they are while this lives.
struct Native {
    _strings: Vec<Vec<u16>>,
    _buttons: Vec<TASKDIALOG_BUTTON>,
    config: TASKDIALOGCONFIG,
}

#[derive(Default)]
struct Strings(Vec<Vec<u16>>);

impl Strings {
    fn add(&mut self, text: &str) -> PCWSTR {
        let text = wide(text);
        let pointer = text.as_ptr();
        self.0.push(text);
        pointer
    }
}

/// `MAKEINTRESOURCE(1)`: the application icon in `windows/factorseal-setup.rc`.
const APP_ICON: PCWSTR = 1 as PCWSTR;

fn native(page: &Page, focus: Option<usize>, state: *const c_void) -> Box<Native> {
    let mut strings = Strings::default();
    let buttons: Vec<TASKDIALOG_BUTTON> = page
        .toggles
        .iter()
        .zip(TOGGLE..)
        .map(|(toggle, id)| TASKDIALOG_BUTTON {
            nButtonID: id,
            pszButtonText: strings.add(&toggle.text()),
        })
        .collect();
    let mut flags = TDF_ALLOW_DIALOG_CANCELLATION;
    if !page.toggles.is_empty() {
        // Without the arrow, which says "go on", not "turn on".
        flags |= TDF_USE_COMMAND_LINKS_NO_ICON;
    }
    if page.progress {
        flags |= TDF_SHOW_MARQUEE_PROGRESS_BAR | TDF_CALLBACK_TIMER;
    }
    if page.expanded {
        flags |= TDF_EXPANDED_BY_DEFAULT;
    }
    let (expanded, expand, collapse) = match &page.details {
        Some(details) => (
            strings.add(details),
            strings.add("Hide details"),
            strings.add("Show details"),
        ),
        None => (std::ptr::null(), std::ptr::null(), std::ptr::null()),
    };
    let config = TASKDIALOGCONFIG {
        cbSize: u32::try_from(std::mem::size_of::<TASKDIALOGCONFIG>()).unwrap_or(0),
        // SAFETY: a null name asks for this executable's own module handle.
        hInstance: unsafe { GetModuleHandleW(std::ptr::null()) },
        dwFlags: flags,
        dwCommonButtons: match page.buttons {
            Buttons::OkCancel => TDCBF_OK_BUTTON | TDCBF_CANCEL_BUTTON,
            Buttons::Close => TDCBF_CLOSE_BUTTON,
            Buttons::Working => TDCBF_CANCEL_BUTTON,
        },
        pszWindowTitle: strings.add(TITLE),
        Anonymous1: TASKDIALOGCONFIG_0 {
            pszMainIcon: match page.icon {
                Icon::App => APP_ICON,
                Icon::Warning => TD_WARNING_ICON,
                Icon::Error => TD_ERROR_ICON,
            },
        },
        pszMainInstruction: strings.add(&page.heading),
        pszContent: strings.add(&page.content),
        cButtons: u32::try_from(buttons.len()).unwrap_or(0),
        pButtons: buttons.as_ptr(),
        nDefaultButton: match (focus, page.buttons) {
            (Some(index), _) => TOGGLE + i32::try_from(index).unwrap_or(0),
            (None, Buttons::OkCancel) => IDOK,
            (None, Buttons::Close) => IDCLOSE,
            (None, Buttons::Working) => IDCANCEL,
        },
        pszExpandedInformation: expanded,
        pszExpandedControlText: expand,
        pszCollapsedControlText: collapse,
        pfCallback: Some(callback),
        lpCallbackData: state as isize,
        // Wide enough for an install folder's path, in dialog units.
        cxWidth: WIDTH,
        ..TASKDIALOGCONFIG::default()
    };
    Box::new(Native {
        _strings: strings.0,
        _buttons: buttons,
        config,
    })
}

/// What the callback needs, reached through `lpCallbackData`. Windows
/// calls back while a message sent from the callback is handled (a
/// navigation sends `TDN_NAVIGATED`), so nothing here is borrowed across a
/// call into Windows.
struct State<'a> {
    page: RefCell<Page>,
    /// The page Windows shows, kept alive while it does.
    native: RefCell<Option<Box<Native>>>,
    handler: RefCell<&'a mut dyn FnMut(Event<'_>) -> Next>,
    working: Cell<bool>,
    progress: Cell<bool>,
    closing: Cell<bool>,
}

fn send(hwnd: HWND, message: i32, wparam: WPARAM, lparam: LPARAM) {
    let Ok(message) = u32::try_from(message) else {
        return;
    };
    // SAFETY: `hwnd` is the task dialog Windows passed to the callback, and
    // every pointer in `lparam` outlives this synchronous call.
    unsafe { SendMessageW(hwnd, message, wparam, lparam) };
}

/// Show the page in `state.page` with the focus on toggle `focus`.
fn navigate(hwnd: HWND, state: &State<'_>, focus: Option<usize>) {
    let page = state.page.borrow().clone();
    state.working.set(page.buttons == Buttons::Working);
    state.progress.set(page.progress);
    let native = native(&page, focus, std::ptr::from_ref(state).cast());
    let config = std::ptr::from_ref(&native.config);
    // The page shown so far stays alive until Windows has moved on.
    let shown = state.native.replace(Some(native));
    send(hwnd, TDM_NAVIGATE_PAGE, 0, config as LPARAM);
    drop(shown);
}

/// Do what the handler asked; whether the dialog closes.
fn apply(hwnd: HWND, state: &State<'_>, next: Next) -> bool {
    match next {
        Next::Stay => false,
        Next::Content(text) => {
            state.page.borrow_mut().content.clone_from(&text);
            let text = wide(&text);
            send(
                hwnd,
                TDM_SET_ELEMENT_TEXT,
                TDE_CONTENT as WPARAM,
                text.as_ptr() as LPARAM,
            );
            false
        }
        Next::Page(page) => {
            *state.page.borrow_mut() = page;
            navigate(hwnd, state, None);
            false
        }
        Next::Close => {
            state.closing.set(true);
            true
        }
    }
}

fn handle(state: &State<'_>, event: Event<'_>) -> Next {
    (state.handler.borrow_mut())(event)
}

unsafe extern "system" fn callback(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    _lparam: LPARAM,
    data: isize,
) -> HRESULT {
    // SAFETY: `data` is the `State` that `run` passed as `lpCallbackData`,
    // alive until `TaskDialogIndirect` returns, and only shared here.
    let state = unsafe { &*(data as *const State<'_>) };
    let Ok(message) = i32::try_from(message) else {
        return S_OK;
    };
    match message {
        TDN_CREATED | TDN_NAVIGATED => {
            if state.working.get() {
                send(hwnd, TDM_ENABLE_BUTTON, IDCANCEL as WPARAM, 0);
            }
            if state.progress.get() {
                send(hwnd, TDM_SET_PROGRESS_BAR_MARQUEE, 1, 0);
            }
            S_OK
        }
        TDN_BUTTON_CLICKED => {
            if state.closing.get() {
                return S_OK;
            }
            let id = i32::try_from(wparam).unwrap_or(0);
            let states: Vec<bool> = state
                .page
                .borrow()
                .toggles
                .iter()
                .map(|toggle| toggle.on)
                .collect();
            if let Some(index) = usize::try_from(id - TOGGLE)
                .ok()
                .filter(|index| *index < states.len())
            {
                if let Some(toggle) = state.page.borrow_mut().toggles.get_mut(index) {
                    toggle.on = !toggle.on;
                }
                navigate(hwnd, state, Some(index));
                return S_FALSE;
            }
            if state.working.get() {
                return S_FALSE;
            }
            let event = if id == IDOK {
                Event::Ok(&states)
            } else {
                Event::Cancel(&states)
            };
            let next = handle(state, event);
            if apply(hwnd, state, next) {
                S_OK
            } else {
                S_FALSE
            }
        }
        TDN_EXPANDO_BUTTON_CLICKED => {
            // Kept for the page shown again after a toggle.
            state.page.borrow_mut().expanded = wparam != 0;
            S_OK
        }
        TDN_TIMER => {
            let next = handle(state, Event::Timer);
            if apply(hwnd, state, next) {
                // Closing goes through a click, which now returns S_OK.
                if let Ok(click) = u32::try_from(TDM_CLICK_BUTTON) {
                    // SAFETY: posted to the dialog Windows passed in.
                    unsafe { PostMessageW(hwnd, click, IDCANCEL as WPARAM, 0) };
                }
            }
            S_OK
        }
        _ => S_OK,
    }
}

/// `TaskDialogIndirect` from Common Controls 6.
fn task_dialog_indirect() -> Result<TaskDialogIndirect, String> {
    let name = wide("comctl32.dll");
    // SAFETY: a null-terminated library name.
    let module = unsafe { LoadLibraryW(name.as_ptr()) };
    if module.is_null() {
        return Err("comctl32.dll can't be loaded".to_owned());
    }
    // SAFETY: a null-terminated function name, in a module just loaded.
    let address = unsafe { GetProcAddress(module, c"TaskDialogIndirect".as_ptr().cast()) };
    address
        // SAFETY: TaskDialogIndirect has exactly this signature.
        .map(|function| unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, TaskDialogIndirect>(
                function,
            )
        })
        .ok_or_else(|| {
            "Windows offers no task dialogs here (Common Controls 6 isn't active)".to_owned()
        })
}

/// Show `page`, then whatever `handler` says, until it closes the dialog.
pub fn run(page: Page, handler: &mut dyn FnMut(Event<'_>) -> Next) -> Result<(), String> {
    let function = task_dialog_indirect()?;
    let state = State {
        working: Cell::new(page.buttons == Buttons::Working),
        progress: Cell::new(page.progress),
        page: RefCell::new(page),
        native: RefCell::new(None),
        handler: RefCell::new(handler),
        closing: Cell::new(false),
    };
    let native = native(
        &state.page.borrow(),
        None,
        std::ptr::from_ref(&state).cast(),
    );
    let config = std::ptr::from_ref(&native.config);
    *state.native.borrow_mut() = Some(native);
    let mut button = 0;
    // SAFETY: `config` and everything it points to live in `state`, which
    // outlives the call; the callback gets `state` through it.
    let result = unsafe {
        function(
            config,
            &raw mut button,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result < 0 {
        return Err(format!("the dialog failed (HRESULT {result:#010x})"));
    }
    Ok(())
}

/// A message with only a Close button.
pub fn message(page: Page) {
    let _ = run(page, &mut |_| Next::Close);
}

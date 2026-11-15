use gpui::{
    AnyElement, App, Context, Div, Entity, EventEmitter, SharedString, Subscription, Window, div,
    prelude::*, rems,
};
use gpui_component::{
    ActiveTheme as _, Disableable as _, Icon, IconName, IndexPath, StyledExt as _,
    button::{Button, ButtonVariants as _},
    h_flex,
    select::{Select, SelectEvent, SelectItem, SelectState},
    switch::Switch,
    v_flex,
};

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    appearance::{self, Choice, TypeScale as _},
    branding::Glyph,
    controls::button,
    settings::DesktopSettings,
    wsl_keyring_import::{self as keyring_import, Check, MoveReport},
};

/// Where a distro's gnome-keyring check or move stands. A run in progress
/// holds the flag that cancels it.
#[derive(Clone)]
enum KeyringMove {
    Checking(Arc<AtomicBool>),
    Checked(Check),
    Moving(Check, Arc<AtomicBool>),
    Moved(MoveReport),
    Failed(String),
}

impl KeyringMove {
    fn cancel(&self) -> Option<&Arc<AtomicBool>> {
        match self {
            Self::Checking(cancel) | Self::Moving(_, cancel) => Some(cancel),
            _ => None,
        }
    }
}

/// `count` and the noun, singular or plural.
fn count(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

/// What Check found, in a sentence or two.
fn check_summary(distro: &str, check: &Check) -> Vec<String> {
    let mut lines = vec![if check.items.is_empty() {
        format!("gnome-keyring in {distro} has no items to move.")
    } else if check.missing.is_empty() {
        format!(
            "{} in gnome-keyring, all already in FactorSeal.",
            count(check.items.len(), "item", "items")
        )
    } else {
        format!(
            "{} in gnome-keyring, {} not in FactorSeal.",
            count(check.items.len(), "item", "items"),
            check.missing.len()
        )
    }];
    let labels: Vec<&str> = check
        .missing
        .iter()
        .filter_map(|item| item.label.as_deref())
        .collect();
    if !labels.is_empty() {
        let unnamed = check.missing.len() - labels.len();
        let mut named = labels.join(", ");
        if unnamed > 0 {
            use std::fmt::Write as _;
            let _ = write!(
                named,
                ", and {} whose name gnome-keyring hides until it is unlocked",
                count(unnamed, "item", "items")
            );
        }
        lines.push(format!("Not in FactorSeal: {named}."));
    }
    if !check.skipped.is_empty() {
        lines.push(format!(
            "{} will not be moved:",
            count(check.skipped.len(), "item", "items")
        ));
        lines.extend(check.skipped.iter().map(keyring_import::skipped_line));
    }
    if !check.missing.is_empty() && check.locked_collections > 0 {
        lines.push(format!(
            "gnome-keyring is locked, so moving asks for its password in a window from {distro}{}. Some items may turn out too large to move once their values are read.",
            if check.locked_collections > 1 {
                format!(", once for each of its {} locked collections", check.locked_collections)
            } else {
                String::new()
            }
        ));
    }
    lines
}

/// What a move did, in a sentence or two.
fn move_summary(report: &MoveReport) -> Vec<String> {
    let mut lines = vec![match (report.added, report.kept) {
        (0, 0) => "Nothing was moved.".to_owned(),
        (added, 0) => format!("Moved {} into FactorSeal.", count(added, "item", "items")),
        (added, kept) => format!(
            "Moved {} into FactorSeal; {} already there.",
            count(added, "item", "items"),
            if kept == 1 {
                "1 was".to_owned()
            } else {
                format!("{kept} were")
            }
        ),
    }];
    if !report.skipped.is_empty() {
        lines.push(format!(
            "{} not moved:",
            count(report.skipped.len(), "item", "items")
        ));
        lines.extend(report.skipped.iter().map(keyring_import::skipped_line));
    }
    lines.extend(
        report
            .skipped_collections
            .iter()
            .map(keyring_import::skipped_collection_line),
    );
    if report.added > 0 {
        lines.push(
            "The items stay in gnome-keyring too. Each program asks here the first time it reads one."
                .to_owned(),
        );
    }
    lines
}

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Theme(Choice),
    Scale(u16),
    Text(Option<u16>),
    Font(Option<String>),
    Idle(u64),
    Maximum(u64),
}

impl Value {
    fn label(&self) -> SharedString {
        match self {
            Self::Theme(choice) => choice.label().into(),
            Self::Scale(value) => format!("{value}%").into(),
            Self::Text(Some(value)) => format!("{value} px").into(),
            Self::Font(Some(value)) => value.clone().into(),
            Self::Text(None) | Self::Font(None) => "System default".into(),
            Self::Idle(seconds) | Self::Maximum(seconds) => {
                if seconds.is_multiple_of(3600) {
                    let hours = seconds / 3600;
                    format!("{hours} {}", if hours == 1 { "hour" } else { "hours" }).into()
                } else if seconds.is_multiple_of(60) {
                    let minutes = seconds / 60;
                    format!(
                        "{minutes} {}",
                        if minutes == 1 { "minute" } else { "minutes" }
                    )
                    .into()
                } else {
                    format!(
                        "{} minutes",
                        std::time::Duration::from_secs(*seconds).as_secs_f64() / 60.
                    )
                    .into()
                }
            }
        }
    }

    fn apply(&self, settings: &mut DesktopSettings) {
        match self {
            Self::Theme(value) => settings.theme = *value,
            Self::Scale(value) => settings.ui_scale = *value,
            Self::Text(value) => settings.text_size = *value,
            Self::Font(value) => settings.font.clone_from(value),
            Self::Idle(value) => settings.idle_seconds = *value,
            Self::Maximum(value) => settings.maximum_seconds = *value,
        }
    }
}

#[derive(Clone)]
struct Item(Value);

impl SelectItem for Item {
    type Value = Value;

    fn title(&self) -> SharedString {
        self.0.label()
    }

    fn value(&self) -> &Value {
        &self.0
    }
}

type Control = Entity<SelectState<Vec<Item>>>;

pub(crate) struct BrowserRow {
    pub(crate) name: &'static str,
    pub(crate) state: SharedString,
    pub(crate) install: Option<AnyElement>,
}

pub(crate) struct Browsers {
    pub(crate) rows: Vec<BrowserRow>,
    pub(crate) notes: Vec<&'static str>,
    pub(crate) error: Option<&'static str>,
    pub(crate) paired: Vec<AnyElement>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Section {
    Appearance,
    Security,
    Browsers,
    WslKeyrings,
    Diagnostics,
}

impl Section {
    pub(crate) fn visible(browsers: bool) -> Vec<Self> {
        Self::visible_with(browsers, cfg!(windows))
    }

    /// The sections shown, with the browser extensions only when a browser
    /// bridge is available and WSL keyrings only on Windows.
    fn visible_with(browsers: bool, wsl: bool) -> Vec<Self> {
        [Self::Appearance, Self::Security]
            .into_iter()
            .chain(browsers.then_some(Self::Browsers))
            .chain(wsl.then_some(Self::WslKeyrings))
            .chain([Self::Diagnostics])
            .collect()
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Appearance => "Appearance",
            Self::Security => "Security",
            Self::Browsers => "Browser extensions",
            Self::WslKeyrings => "WSL keyrings",
            Self::Diagnostics => "Diagnostics",
        }
    }

    pub(crate) fn icon(self) -> Icon {
        match self {
            Self::Appearance => IconName::Palette.into(),
            Self::Security => Glyph::Lock.into(),
            Self::Browsers => IconName::Globe.into(),
            Self::WslKeyrings => Glyph::Key.into(),
            Self::Diagnostics => Glyph::Bug.into(),
        }
    }
}

pub(crate) struct ReportIssue;

impl EventEmitter<ReportIssue> for SettingsView {}

pub(crate) struct SettingsView {
    section: Section,
    controls: Vec<Control>,
    error: Option<&'static str>,
    export_busy: bool,
    export_complete: bool,
    /// Read when WSL keyrings is first opened.
    wsl_distros: Option<crate::wsl_distros::WslDistros>,
    /// Each distro's gnome-keyring check or move.
    keyring_moves: HashMap<String, KeyringMove>,
    _subscriptions: Vec<Subscription>,
}

fn values(settings: &DesktopSettings) -> [Value; 6] {
    [
        Value::Theme(settings.theme),
        Value::Scale(settings.ui_scale),
        Value::Text(settings.text_size),
        Value::Font(settings.font.clone()),
        Value::Idle(settings.idle_seconds),
        Value::Maximum(settings.maximum_seconds),
    ]
}

fn options(cx: &App) -> [Vec<Value>; 6] {
    let mut fonts = cx.text_system().all_font_names();
    fonts.sort_unstable();
    fonts.dedup();
    [
        Choice::all().map(Value::Theme).collect(),
        [80, 90, 100, 110, 125, 150, 175, 200]
            .into_iter()
            .map(Value::Scale)
            .collect(),
        std::iter::once(Value::Text(None))
            .chain(
                [12, 14, 16, 18, 20, 24]
                    .into_iter()
                    .map(|size| Value::Text(Some(size))),
            )
            .collect(),
        std::iter::once(Value::Font(None))
            .chain(fonts.into_iter().map(|font| Value::Font(Some(font))))
            .collect(),
        [60, 300, 900, 1800, 3600]
            .into_iter()
            .map(Value::Idle)
            .collect(),
        [900, 3600, 14_400, 28_800, 86_400]
            .into_iter()
            .map(Value::Maximum)
            .collect(),
    ]
}

impl SettingsView {
    pub(crate) fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let current = values(appearance::current(cx));
        let controls: Vec<_> = options(cx)
            .into_iter()
            .zip(current)
            .map(|(mut options, selected)| {
                if !options.contains(&selected) {
                    options.push(selected.clone());
                }
                let index = options
                    .iter()
                    .position(|value| value == &selected)
                    .map(|index| IndexPath::default().row(index));
                cx.new(|cx| {
                    SelectState::new(
                        options.into_iter().map(Item).collect::<Vec<_>>(),
                        index,
                        window,
                        cx,
                    )
                    .searchable(true)
                })
            })
            .collect();
        let subscriptions = controls
            .iter()
            .map(|control| {
                cx.subscribe_in(
                    control,
                    window,
                    |view, _, event: &SelectEvent<Vec<Item>>, window, cx| {
                        if let SelectEvent::Confirm(Some(value)) = event {
                            let mut settings = appearance::current(cx).clone();
                            value.apply(&mut settings);
                            view.save(settings, window, cx);
                        }
                    },
                )
            })
            .collect();
        Self {
            section: Section::Appearance,
            controls,
            error: None,
            export_busy: false,
            export_complete: false,
            wsl_distros: None,
            keyring_moves: HashMap::new(),
            _subscriptions: subscriptions,
        }
    }

    pub(crate) fn section(&self, browsers: bool) -> Section {
        if Section::visible(browsers).contains(&self.section) {
            self.section
        } else {
            Section::Appearance
        }
    }

    pub(crate) fn set_section(&mut self, section: Section, cx: &mut Context<Self>) {
        self.section = section;
        self.error = None;
        if section == Section::WslKeyrings {
            Self::load_wsl_distros(cx);
        }
        cx.notify();
    }

    fn load_wsl_distros(cx: &mut Context<Self>) {
        cx.spawn(async move |view, cx| {
            let distros = smol::unblock(crate::wsl_distros::WslDistros::load).await;
            let _ = view.update(cx, |view, cx| {
                view.wsl_distros = Some(distros);
                cx.notify();
            });
        })
        .detach();
    }

    fn save(&mut self, settings: DesktopSettings, window: &mut Window, cx: &mut Context<Self>) {
        self.error = if settings.idle_seconds > settings.maximum_seconds {
            Some("The inactivity time cannot be longer than the maximum time unsealed.")
        } else if let Err(error) = appearance::update(settings, cx) {
            factorseal::diagnostics::event("desktop", "save_settings", "error");
            eprintln!("could not save desktop settings: {error:#}");
            Some("Could not save settings.")
        } else {
            None
        };
        if self.error.is_some() {
            self.sync_controls(window, cx);
        }
        cx.notify();
    }

    fn sync_controls(&self, window: &mut Window, cx: &mut Context<Self>) {
        for (control, value) in self.controls.iter().zip(values(appearance::current(cx))) {
            control.update(cx, |control, cx| {
                control.set_selected_value(&value, window, cx);
            });
        }
    }

    fn default_appearance(settings: &DesktopSettings) -> DesktopSettings {
        let defaults = DesktopSettings::default();
        DesktopSettings {
            theme: defaults.theme,
            ui_scale: defaults.ui_scale,
            text_size: defaults.text_size,
            font: defaults.font,
            reduced_motion: defaults.reduced_motion,
            website_icons: defaults.website_icons,
            ..settings.clone()
        }
    }

    fn reset_button(cx: &mut Context<Self>) -> Button {
        let current = appearance::current(cx);
        button("reset-appearance")
            .icon(IconName::Undo2)
            .label("Reset to defaults")
            .disabled(*current == Self::default_appearance(current))
            .on_click(cx.listener(|view, _, window, cx| {
                let settings = Self::default_appearance(appearance::current(cx));
                view.save(settings, window, cx);
                view.sync_controls(window, cx);
            }))
    }

    fn select(&self, label: &'static str, index: usize) -> Div {
        div()
            .w(rems(18.))
            .max_w_full()
            .flex_none()
            .child(crate::controls::hover_field(
                ("settings-select", index),
                Select::new(&self.controls[index])
                    .accessibility_label(label)
                    .search_placeholder(label)
                    .w_full(),
            ))
    }

    fn switch(
        id: &'static str,
        label: &'static str,
        checked: bool,
        apply: fn(&mut DesktopSettings, bool),
        cx: &mut Context<Self>,
    ) -> crate::controls::ToggleFrame {
        crate::controls::toggle_frame(
            format!("{id}-frame"),
            Switch::new(id)
                .accessibility_label(label)
                .checked(checked)
                .on_click(cx.listener(move |view, checked: &bool, window, cx| {
                    let mut settings = appearance::current(cx).clone();
                    apply(&mut settings, *checked);
                    view.save(settings, window, cx);
                })),
        )
    }

    fn setting(label: impl Into<SharedString>, control: impl IntoElement, cx: &App) -> Div {
        h_flex()
            .w_full()
            .min_h_12()
            .items_center()
            .justify_between()
            .gap_4()
            .py_1()
            .child(
                div()
                    .min_w_0()
                    .text_color(cx.theme().muted_foreground)
                    .child(label.into()),
            )
            .child(control)
    }

    fn list(rows: impl IntoIterator<Item = Div>, cx: &App) -> Div {
        let border = cx.theme().border;
        v_flex().w_full().children(
            rows.into_iter()
                .map(move |row| row.border_b_1().border_color(border)),
        )
    }

    fn note(text: impl IntoElement, cx: &App) -> Div {
        div()
            .text_body()
            .text_color(cx.theme().muted_foreground)
            .child(text)
    }

    fn appearance_rows(&self, cx: &mut Context<Self>) -> Vec<Div> {
        let reduced_motion = appearance::current(cx).reduced_motion;
        let website_icons = appearance::current(cx).website_icons;
        vec![
            Self::setting("Theme", self.select("Theme", 0), cx),
            Self::setting("UI scale", self.select("UI scale", 1), cx),
            Self::setting("Text size", self.select("Text size", 2), cx),
            Self::setting("Font", self.select("Font", 3), cx),
            Self::setting(
                "Reduced motion",
                Self::switch(
                    "reduced-motion",
                    "Reduced motion",
                    reduced_motion,
                    |settings, value| settings.reduced_motion = value,
                    cx,
                ),
                cx,
            ),
            Self::setting(
                "Show website icons",
                Self::switch(
                    "website-icons",
                    "Show website icons",
                    website_icons,
                    |settings, value| settings.website_icons = value,
                    cx,
                ),
                cx,
            ),
        ]
    }

    fn security_rows(&self, cx: &App) -> Vec<Div> {
        vec![
            Self::setting(
                "Seal after inactivity",
                self.select("Seal after inactivity", 4),
                cx,
            ),
            Self::setting(
                "Maximum time unsealed",
                self.select("Maximum time unsealed", 5),
                cx,
            ),
        ]
    }

    fn crash_reports_row(cx: &mut Context<Self>) -> Div {
        let checked = appearance::current(cx).automatic_crash_reports;
        Self::setting(
            "Automatically send crash reports",
            Self::switch(
                "automatic-crash-reports",
                "Automatically send crash reports",
                checked,
                |settings, value| settings.automatic_crash_reports = value,
                cx,
            ),
            cx,
        )
    }

    fn diagnostics_text() -> [&'static str; 3] {
        [
            "Crash reports include recent actions, timings and backtraces, but never secret values or panic messages. Saved reports can still be exported.",
            if crate::crash_reporting::configured() {
                "When automatic reporting is on, crash reports from Desktop and its vault helper are sent in the background, including reports saved before a restart."
            } else {
                "Reports cannot be sent right now. They stay on this computer."
            },
            "Report an issue opens a form where you describe what went wrong. Sending it includes recent logs, even when automatic crash reports are off.",
        ]
    }

    fn export_button(&self, cx: &mut Context<Self>) -> Button {
        button("export-diagnostics")
            .icon(Glyph::Download)
            .loading(self.export_busy)
            .label(if self.export_busy {
                "Exporting…"
            } else {
                "Export diagnostics…"
            })
            .disabled(self.export_busy)
            .on_click(cx.listener(|view, _, _, cx| view.export_diagnostics(cx)))
    }

    fn report_button(cx: &mut Context<Self>) -> Button {
        button("report-issue-from-settings")
            .icon(Glyph::Bug)
            .label("Report an issue")
            .on_click(cx.listener(|_, _, _, cx| cx.emit(ReportIssue)))
    }

    fn export_status(&self, cx: &App) -> Option<Div> {
        self.export_complete.then(|| {
            Self::note(
                "Diagnostics exported. Review the file before sharing it.",
                cx,
            )
        })
    }

    fn browser_rows(rows: Vec<BrowserRow>, cx: &App) -> Vec<Div> {
        let muted = cx.theme().muted_foreground;
        rows.into_iter()
            .map(|row| {
                h_flex()
                    .w_full()
                    .min_h_12()
                    .items_center()
                    .gap_4()
                    .py_1()
                    .child(
                        div()
                            .w(rems(140. / 16.))
                            .flex_none()
                            .text_color(muted)
                            .child(row.name),
                    )
                    .child(div().flex_1().child(row.state))
                    .children(row.install)
            })
            .collect()
    }

    fn browser_notes(notes: Vec<&'static str>, error: Option<&'static str>, cx: &App) -> Div {
        v_flex()
            .gap_2()
            .children(notes.into_iter().map(|note| Self::note(note, cx)))
            .children(
                error.map(|error| div().text_body().text_color(cx.theme().danger).child(error)),
            )
    }

    fn paired_rows(paired: Vec<AnyElement>) -> Vec<Div> {
        paired
            .into_iter()
            .map(|button| h_flex().w_full().py_2().child(button))
            .collect()
    }

    /// The distros listed: those registered, then any switched on that are
    /// no longer registered, so they can still be switched off.
    fn wsl_rows(registered: &[String], saved: &[String]) -> Vec<(String, bool)> {
        registered
            .iter()
            .chain(saved.iter().filter(|distro| !registered.contains(distro)))
            .map(|distro| (distro.clone(), saved.contains(distro)))
            .collect()
    }

    fn wsl_switch(
        distro: String,
        checked: bool,
        broker_installed: bool,
        cx: &mut Context<Self>,
    ) -> crate::controls::ToggleFrame {
        let id = SharedString::from(format!("wsl-keyring-{distro}"));
        crate::controls::toggle_frame(
            SharedString::from(format!("{id}-frame")),
            Switch::new(id)
                .accessibility_label(format!("Use this vault as the keyring of {distro}"))
                .checked(checked)
                // Without the broker, a distro can only be switched off.
                .disabled(!broker_installed && !checked)
                .on_click(cx.listener(move |view, checked: &bool, window, cx| {
                    let mut settings = appearance::current(cx).clone();
                    settings.wsl_keyrings.retain(|saved| saved != &distro);
                    if *checked {
                        settings.wsl_keyrings.push(distro.clone());
                    }
                    view.save(settings, window, cx);
                })),
        )
    }

    /// Whether `cancel` is still the flag of `distro`'s run, so a result
    /// isn't applied after another run took its place.
    fn keyring_run_current(&self, distro: &str, cancel: &Arc<AtomicBool>) -> bool {
        self.keyring_moves
            .get(distro)
            .and_then(KeyringMove::cancel)
            .is_some_and(|current| Arc::ptr_eq(current, cancel))
    }

    /// Check: list `distro`'s gnome-keyring (starting WSL) and compare it
    /// with the vault.
    fn check_keyring(&mut self, distro: String, cx: &mut Context<Self>) {
        let (Some((runtime, metadata)), Some(wsl)) =
            (crate::app::unsealed_vault(cx), keyring_import::system())
        else {
            return;
        };
        let cancel = Arc::new(AtomicBool::new(false));
        self.keyring_moves
            .insert(distro.clone(), KeyringMove::Checking(Arc::clone(&cancel)));
        cx.notify();
        cx.spawn(async move |view, cx| {
            let (run_distro, flag) = (distro.clone(), Arc::clone(&cancel));
            let result = smol::unblock(move || {
                keyring_import::check(
                    wsl,
                    &run_distro,
                    || runtime.keyring_fingerprints(&metadata, &run_distro),
                    &flag,
                )
            })
            .await;
            let _ = view.update(cx, |view, cx| {
                if !view.keyring_run_current(&distro, &cancel) {
                    return;
                }
                match result {
                    Ok(check) => {
                        view.keyring_moves
                            .insert(distro, KeyringMove::Checked(check));
                    }
                    Err(_) if cancel.load(Ordering::SeqCst) => {
                        view.keyring_moves.remove(&distro);
                    }
                    Err(error) => {
                        view.keyring_moves
                            .insert(distro, KeyringMove::Failed(error));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// Move: export `distro`'s gnome-keyring (unlocking it) and restore all
    /// of it; items already in the vault are kept as they are.
    fn move_keyring(&mut self, distro: String, check: Check, cx: &mut Context<Self>) {
        let (Some((runtime, metadata)), Some(wsl)) =
            (crate::app::unsealed_vault(cx), keyring_import::system())
        else {
            return;
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let locked = check.locked_collections;
        self.keyring_moves.insert(
            distro.clone(),
            KeyringMove::Moving(check.clone(), Arc::clone(&cancel)),
        );
        cx.notify();
        cx.spawn(async move |view, cx| {
            let (run_distro, flag) = (distro.clone(), Arc::clone(&cancel));
            let result = smol::unblock(move || {
                keyring_import::move_items(
                    wsl,
                    &run_distro,
                    locked,
                    |archive| runtime.restore_keyring_archive(&metadata, archive),
                    &flag,
                )
            })
            .await;
            cx.update(|cx| {
                if result.is_ok() {
                    crate::app::refresh_vault(cx);
                }
            });
            let _ = view.update(cx, |view, cx| {
                if !view.keyring_run_current(&distro, &cancel) {
                    return;
                }
                let state = match result {
                    Ok(report) => KeyringMove::Moved(report),
                    Err(_) if cancel.load(Ordering::SeqCst) => KeyringMove::Checked(check),
                    Err(error) => KeyringMove::Failed(error),
                };
                view.keyring_moves.insert(distro, state);
                cx.notify();
            });
        })
        .detach();
    }

    /// The buttons beside a distro's switch: Check, Move, Cancel.
    fn keyring_buttons(
        &self,
        distro: &str,
        unsealed: bool,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        let state = self.keyring_moves.get(distro);
        let busy = state.and_then(KeyringMove::cancel);
        let mut buttons = Vec::new();
        if let Some(cancel) = busy {
            let cancel = Arc::clone(cancel);
            let cancelling = cancel.load(Ordering::SeqCst);
            buttons.push(
                button(SharedString::from(format!("keyring-cancel-{distro}")))
                    .label(if cancelling {
                        "Cancelling…"
                    } else {
                        "Cancel"
                    })
                    .disabled(cancelling)
                    .on_click(cx.listener(move |_, _, _, cx| {
                        cancel.store(true, Ordering::SeqCst);
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        if let Some(KeyringMove::Checked(check)) = state
            && !check.missing.is_empty()
        {
            let (distro, check) = (distro.to_owned(), check.clone());
            buttons.push(
                button(SharedString::from(format!("keyring-move-{distro}")))
                    .primary()
                    .icon(Glyph::Transfer)
                    .label(format!(
                        "Move {}",
                        count(check.missing.len(), "item", "items")
                    ))
                    .disabled(!unsealed)
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.move_keyring(distro.clone(), check.clone(), cx);
                    }))
                    .into_any_element(),
            );
        }
        let checking = matches!(state, Some(KeyringMove::Checking(_)));
        let again = matches!(
            state,
            Some(KeyringMove::Checked(_) | KeyringMove::Moved(_) | KeyringMove::Failed(_))
        );
        let owned = distro.to_owned();
        buttons.push(
            button(SharedString::from(format!("keyring-check-{distro}")))
                .loading(checking)
                .label(if checking {
                    "Checking…"
                } else if again {
                    "Check again"
                } else {
                    "Check gnome-keyring"
                })
                .accessibility_label(format!("Check gnome-keyring in {distro}"))
                .disabled(!unsealed || busy.is_some())
                .on_click(cx.listener(move |view, _, _, cx| {
                    view.check_keyring(owned.clone(), cx);
                }))
                .into_any_element(),
        );
        buttons
    }

    /// What a distro's check or move says, under its row.
    fn keyring_status(&self, distro: &str, cx: &App) -> Option<Div> {
        let theme = cx.theme();
        let (lines, color) = match self.keyring_moves.get(distro)? {
            KeyringMove::Checking(_) => (
                vec![format!(
                    "Reading gnome-keyring in {distro}. WSL may have to start it first."
                )],
                theme.muted_foreground,
            ),
            KeyringMove::Checked(check) => (check_summary(distro, check), theme.foreground),
            KeyringMove::Moving(check, _) => (
                vec![if check.locked_collections > 0 {
                    format!(
                        "Moving… gnome-keyring may ask for its password in a window from {distro}."
                    )
                } else {
                    "Moving…".to_owned()
                }],
                theme.muted_foreground,
            ),
            KeyringMove::Moved(report) => (move_summary(report), theme.foreground),
            KeyringMove::Failed(error) => (vec![error.clone()], theme.danger),
        };
        Some(
            v_flex()
                .gap_1()
                .pb_2()
                .text_body()
                .text_color(color)
                .children(lines.into_iter().map(|line| div().child(line))),
        )
    }

    fn wsl_row(
        &self,
        distro: String,
        checked: bool,
        broker_installed: bool,
        unsealed: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let switch = Self::wsl_switch(distro.clone(), checked, broker_installed, cx);
        let buttons = self.keyring_buttons(&distro, unsealed, cx);
        let status = self.keyring_status(&distro, cx);
        v_flex()
            .w_full()
            .child(Self::setting(
                distro,
                h_flex()
                    .flex_wrap()
                    .justify_end()
                    .gap_2()
                    .items_center()
                    .children(buttons)
                    .child(switch),
                cx,
            ))
            .children(status)
    }

    fn wsl_keyrings(&self, cx: &mut Context<Self>) -> Div {
        let panel = v_flex().gap_3();
        let Some(distros) = self.wsl_distros.clone() else {
            return panel.child(Self::note("Looking for WSL distros…", cx));
        };
        let saved = appearance::current(cx).wsl_keyrings.clone();
        let registered = distros.registered.as_deref().unwrap_or_default();
        let unsealed = crate::app::unsealed_vault(cx).is_some();
        let rows: Vec<_> = Self::wsl_rows(registered, &saved)
            .into_iter()
            .map(|(distro, checked)| {
                self.wsl_row(distro, checked, distros.broker_installed, unsealed, cx)
            })
            .collect();
        let danger = cx.theme().danger;
        let rows_empty = rows.is_empty();
        panel
            .when(rows.is_empty(), |panel| {
                panel.child(Self::note(
                    "No WSL distros are installed for this Windows user.",
                    cx,
                ))
            })
            .when(!rows.is_empty(), |panel| panel.child(Self::list(rows, cx)))
            .child(Self::note(
                "Programs in a distro switched on here use this vault as their keyring (org.freedesktop.secrets) through factorseal wsl-keyring, set up in the distro with factorseal wsl-setup. Each program asks here before it reads or writes an item, and its access ends when the vault seals.",
                cx,
            ))
            .child(Self::note(
                "FactorSeal cannot verify which program in WSL is asking: the name it shows comes from WSL, and any program there can act as another.",
                cx,
            ))
            .when(!rows_empty, |panel| {
                panel.child(Self::note(
                    if unsealed {
                        "Check gnome-keyring starts the distro and counts the items its gnome-keyring has that FactorSeal lacks, without unlocking it. Moving copies them into this vault; gnome-keyring keeps its own."
                    } else {
                        "Unlock the vault to check a distro's gnome-keyring for items to move here."
                    },
                    cx,
                ))
            })
            .when_some(crate::app::wsl_keyrings_error(cx), |panel, error| {
                panel.child(div().text_body().text_color(danger).child(format!(
                    "The vault did not take the last switch: {error}. The switches show what it still has."
                )))
            })
            .when(!distros.broker_installed, |panel| {
                panel.child(div().text_body().text_color(danger).child(
                    "The WSL broker (factorseal-wsl-broker.exe) is not installed beside FactorSeal, so no distro can use this vault.",
                ))
            })
            .when_some(distros.registered.err(), |panel, error| {
                panel.child(div().text_body().text_color(danger).child(format!(
                    "Could not list the WSL distros: {error}"
                )))
            })
    }

    fn diagnostics(&self, cx: &mut Context<Self>) -> Div {
        let crash_reports = Self::crash_reports_row(cx);
        let export = self.export_button(cx);
        v_flex()
            .gap_3()
            .child(Self::list([crash_reports], cx))
            .children(Self::diagnostics_text().map(|text| Self::note(text, cx)))
            .child(
                h_flex()
                    .flex_wrap()
                    .gap_3()
                    .items_center()
                    .child(export)
                    .child(Self::report_button(cx))
                    .children(self.export_status(cx)),
            )
    }

    fn browsers(browsers: Browsers, cx: &App) -> Div {
        v_flex()
            .gap_3()
            .child(Self::list(Self::browser_rows(browsers.rows, cx), cx))
            .child(Self::browser_notes(browsers.notes, browsers.error, cx))
            .when(!browsers.paired.is_empty(), |panel| {
                panel
                    .child(
                        div()
                            .pt_3()
                            .font_semibold()
                            .child("Paired browser profiles"),
                    )
                    .child(Self::list(Self::paired_rows(browsers.paired), cx))
            })
    }

    pub(crate) fn content(
        &mut self,
        browsers: Option<Browsers>,
        protection: AnyElement,
        cx: &mut Context<Self>,
    ) -> Div {
        let content = match self.section(browsers.is_some()) {
            Section::Appearance => v_flex()
                .gap_3()
                .child(Self::list(self.appearance_rows(cx), cx))
                .child(Self::note(
                    "Icons are fetched from DuckDuckGo by website name and kept only while the vault is unsealed.",
                    cx,
                ))
                .child(h_flex().child(Self::reset_button(cx))),
            Section::Security => v_flex()
                .gap_3()
                .child(Self::list(self.security_rows(cx), cx))
                .child(Self::note(
                    "Applies the next time you unlock the vault.",
                    cx,
                ))
                .child(h_flex().text_body().child(protection)),
            Section::Browsers => browsers.map_or_else(div, |browsers| Self::browsers(browsers, cx)),
            Section::WslKeyrings => self.wsl_keyrings(cx),
            Section::Diagnostics => self.diagnostics(cx),
        };
        let danger = cx.theme().danger;
        content.w_full().when_some(self.error, |content, error| {
            content.child(div().text_color(danger).child(error))
        })
    }

    fn export_diagnostics(&mut self, cx: &mut Context<Self>) {
        self.export_busy = true;
        self.export_complete = false;
        self.error = None;
        cx.notify();
        cx.spawn(async move |view, cx| {
            let chosen = rfd::AsyncFileDialog::new()
                .add_filter("Diagnostic report", &["json"])
                .set_file_name("factorseal-diagnostics.json")
                .save_file()
                .await;
            let result = if let Some(chosen) = chosen {
                let path = chosen.path().to_owned();
                Some(smol::unblock(move || factorseal::diagnostics::export(&path)).await)
            } else {
                None
            };
            let _ = view.update(cx, |view, cx| {
                view.export_busy = false;
                match result {
                    Some(Ok(())) => view.export_complete = true,
                    Some(Err(_)) => view.error = Some("Could not export diagnostics. Choose a writable location and try again."),
                    None => {}
                }
                cx.notify();
            });
        }).detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resetting_appearance_keeps_other_settings() {
        let generator = factorseal::personal::generator::Options {
            style: factorseal::personal::generator::Style::Random,
            length: 32,
            words: 18,
            digits: false,
            symbols: true,
        };
        let settings = DesktopSettings {
            device_name: Some("laptop".into()),
            theme: Choice::all()
                .find(|choice| *choice != Choice::default())
                .unwrap(),
            ui_scale: 150,
            text_size: Some(18),
            font: Some("Inter".into()),
            reduced_motion: true,
            website_icons: false,
            automatic_crash_reports: false,
            idle_seconds: 60,
            maximum_seconds: 900,
            generator,
            window: None,
            page: None,
            wsl_keyrings: vec!["NixOS".into()],
        };
        assert_eq!(
            SettingsView::default_appearance(&settings),
            DesktopSettings {
                device_name: Some("laptop".into()),
                automatic_crash_reports: false,
                idle_seconds: 60,
                maximum_seconds: 900,
                generator,
                wsl_keyrings: vec!["NixOS".into()],
                ..DesktopSettings::default()
            }
        );
    }

    #[test]
    fn browser_extensions_tab_shows_only_when_available() {
        let sections = |browsers| Section::visible_with(browsers, false);
        assert_eq!(
            sections(false),
            [Section::Appearance, Section::Security, Section::Diagnostics]
        );
        assert_eq!(
            sections(true),
            [
                Section::Appearance,
                Section::Security,
                Section::Browsers,
                Section::Diagnostics
            ]
        );
        assert_eq!(
            Section::visible_with(false, true),
            [
                Section::Appearance,
                Section::Security,
                Section::WslKeyrings,
                Section::Diagnostics
            ]
        );
    }

    #[test]
    fn wsl_keyrings_list_registered_distros_and_switched_on_leftovers() {
        let names = |names: &[&str]| {
            names
                .iter()
                .map(|&name| name.to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            SettingsView::wsl_rows(&names(&["NixOS", "Ubuntu"]), &names(&["Ubuntu", "Gone"])),
            [
                ("NixOS".to_owned(), false),
                ("Ubuntu".to_owned(), true),
                ("Gone".to_owned(), true),
            ]
        );
    }
}

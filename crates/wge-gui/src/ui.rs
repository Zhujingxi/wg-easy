use crate::{
    backend::{Backend, Command, Event, Intent},
    form,
    settings::Settings,
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    Disableable, Icon, Sizable,
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
    switch::Switch,
};
use gpui_kit::{prelude::*, *};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wge_ipc::{
    ConnectionState, ErrorCode, Request, Response, SensitiveText, Snapshot, Tunnel, TunnelId,
};

static EDITOR_GENERATION: AtomicU64 = AtomicU64::new(0);

const PAPER: u32 = 0xf8f9f6;
const INK: u32 = 0x172e2b;
const MUTED: u32 = 0x586d65;
const LINE: u32 = 0xe2e8e2;
const GREEN: u32 = 0x24785f;
const WASH: u32 = 0xeaf2ec;
fn tr(key: &str) -> SharedString {
    rust_i18n::t!(key).into_owned().into()
}
fn small(text: impl Into<SharedString>) -> Div {
    div().text_sm().text_color(rgb(MUTED)).child(text.into())
}
fn heading(text: impl Into<SharedString>) -> Div {
    div()
        .text_xl()
        .font_weight(FontWeight::SEMIBOLD)
        .child(text.into())
}
fn group(title: &str, number: &str) -> Div {
    div()
        .flex()
        .items_center()
        .gap_3()
        .mb_3()
        .child(
            div()
                .text_xs()
                .text_color(rgb(GREEN))
                .bg(rgb(WASH))
                .rounded_full()
                .px_2()
                .py_1()
                .child(number.to_owned()),
        )
        .child(div().font_weight(FontWeight::SEMIBOLD).child(tr(title)))
}
fn panel() -> Div {
    div()
        .bg(rgb(0xffffff))
        .border_1()
        .border_color(rgb(LINE))
        .rounded_xl()
        .p_5()
}
fn state_text(state: ConnectionState) -> SharedString {
    tr(match state {
        ConnectionState::Off => "off",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Connected => "connected",
        ConnectionState::NoHandshake => "no_handshake",
        ConnectionState::Error => "connection_error",
    })
}
fn state_color(state: ConnectionState) -> Rgba {
    rgb(match state {
        ConnectionState::Connected => GREEN,
        ConnectionState::Connecting | ConnectionState::NoHandshake => 0xa16a31,
        ConnectionState::Error => 0xab544b,
        ConnectionState::Off => MUTED,
    })
}
fn status(state: ConnectionState) -> Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .text_sm()
        .text_color(state_color(state))
        .child(div().size(px(6.)).rounded_full().bg(state_color(state)))
        .child(state_text(state))
}
fn enabled(state: ConnectionState) -> bool {
    !matches!(state, ConnectionState::Off | ConnectionState::Error)
}
fn bytes(value: u64) -> String {
    if value < 1024 {
        format!("{value} B")
    } else if value < 1024 * 1024 {
        format!("{:.1} KiB", value as f64 / 1024.)
    } else if value < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", value as f64 / (1024. * 1024.))
    } else {
        format!("{:.2} GiB", value as f64 / (1024. * 1024. * 1024.))
    }
}

struct Editor {
    tunnel: Tunnel,
    fields: BTreeMap<String, Entity<InputState>>,
    _subscriptions: Vec<Subscription>,
    peers: usize,
    all_traffic: bool,
    advanced: bool,
    submitted: bool,
    revealed: Option<SensitiveText>,
    generation: u64,
    qr: Option<(String, Arc<Image>)>,
}
impl Editor {
    fn values(&self, cx: &App) -> form::Values {
        self.fields
            .iter()
            .map(|(id, input)| {
                (
                    id.clone(),
                    zeroize::Zeroizing::new(input.read(cx).text().to_string()),
                )
            })
            .collect()
    }
}
enum Confirm {
    Export(TunnelId, String),
    Delete(TunnelId, String),
}

pub struct MainView {
    backend: Backend,
    snapshot: Snapshot,
    editor: Option<Editor>,
    selected: Option<TunnelId>,
    settings: Settings,
    show_settings: bool,
    confirmation: Option<Confirm>,
    notice: Option<SharedString>,
    offline: bool,
    busy: bool,
    focus: FocusHandle,
}
impl MainView {
    pub fn new(
        backend: Backend,
        snapshot: Snapshot,
        settings: Settings,
        offline: bool,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.spawn(async move |view, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                if view
                    .update(cx, |view, cx| {
                        if view.editor.is_none() && !view.show_settings {
                            cx.notify();
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        Self {
            backend,
            snapshot: snapshot.clone(),
            editor: None,
            selected: snapshot
                .tunnels
                .iter()
                .find(|t| t.saved)
                .map(|t| t.id.clone()),
            settings,
            show_settings: false,
            confirmation: None,
            notice: None,
            offline,
            busy: false,
            focus: cx.focus_handle(),
        }
    }
    fn input(
        &self,
        value: String,
        masked: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> (Entity<InputState>, Subscription) {
        let input = cx.new(|cx| {
            let mut input = InputState::new(window, cx).masked(masked);
            input.set_value(value, window, cx);
            input
        });
        let sub = cx.subscribe_in(&input, window, |_, _, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        });
        (input, sub)
    }
    fn edit(&mut self, tunnel: Tunnel, window: &mut Window, cx: &mut Context<Self>) {
        self.clear_secrets(window, cx);
        self.clear_editor();
        let generation = EDITOR_GENERATION.fetch_add(1, Ordering::Relaxed);
        let peers = tunnel.config.peers.len().max(1);
        let all_traffic = tunnel.config.peers.is_empty() || tunnel.config.is_all_traffic();
        let mut values = form::values(&tunnel.config, &tunnel.name);
        if tunnel.config.peers.is_empty() {
            for field in ["endpoint", "public_key", "routes", "keepalive", "psk"] {
                values.insert(form::key(0, field), String::new().into());
            }
        }
        let mut fields = BTreeMap::new();
        let mut subscriptions = Vec::new();
        for (id, value) in values {
            let (input, sub) = self.input(value.to_string(), id.ends_with(".psk"), window, cx);
            fields.insert(id, input);
            subscriptions.push(sub);
        }
        self.selected = Some(tunnel.id.clone());
        self.editor = Some(Editor {
            tunnel,
            fields,
            _subscriptions: subscriptions,
            peers,
            all_traffic,
            advanced: false,
            submitted: false,
            revealed: None,
            generation,
            qr: None,
        });
        self.show_settings = false;
        self.notice = None;
        self.busy = false;
        cx.notify();
    }
    pub fn clear_secrets(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(editor) = &mut self.editor {
            editor.revealed = None;
            for (key, input) in &editor.fields {
                if key.ends_with(".psk") {
                    input.update(cx, |input, cx| input.set_value("", window, cx));
                }
            }
        }
    }
    fn clear_editor(&mut self) {
        if let Some(editor) = self.editor.take()
            && !editor.tunnel.saved
        {
            self.backend.send(
                Request::DiscardDraft {
                    id: editor.tunnel.id,
                },
                Intent::Refresh,
            );
        }
    }
    fn send(&mut self, request: Request, intent: Intent, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        self.notice = None;
        self.busy = true;
        self.backend.send(request, intent);
        cx.notify();
    }
    pub fn event(&mut self, event: Event, window: &mut Window, cx: &mut Context<Self>) {
        match event {
            Event::Offline => {
                self.offline = true;
                self.busy = false;
            }
            Event::Error(key) => {
                self.notice = Some(tr(key));
                self.busy = false;
            }
            Event::Reply(intent, response) => {
                self.offline = false;
                if !matches!(intent, Intent::Refresh) {
                    self.busy = false;
                }
                match response {
                    Response::Snapshot(snapshot) => self.snapshot = snapshot,
                    Response::Tunnel(tunnel) => match intent {
                        Intent::Edit => self.edit(tunnel, window, cx),
                        Intent::SaveConnect => {
                            self.clear_secrets(window, cx);
                            if let Some(editor) = &mut self.editor {
                                editor.tunnel.saved = true;
                            }
                            self.selected = Some(tunnel.id.clone());
                            self.editor = None;
                            self.send(Request::Connect { id: tunnel.id }, Intent::Action, cx);
                        }
                        _ => {
                            if let Some(old) =
                                self.snapshot.tunnels.iter_mut().find(|t| t.id == tunnel.id)
                            {
                                *old = tunnel;
                            } else {
                                self.snapshot.tunnels.push(tunnel);
                            }
                        }
                    },
                    Response::Secret(secret) => {
                        if let Intent::Reveal(id, generation) = intent
                            && let Some(editor) = &mut self.editor
                            && editor.tunnel.id == id
                            && editor.generation == generation
                        {
                            editor.revealed = Some(secret);
                        }
                    }
                    Response::Error(error) => {
                        self.notice = Some(if let Some(conflict) = error.conflict {
                            rust_i18n::t!(
                                "conflict",
                                name = conflict.tunnel_name,
                                range = conflict.requested_range,
                                other = conflict.active_range
                            )
                            .into_owned()
                            .into()
                        } else {
                            tr(error_key(error.code))
                        });
                    }
                    Response::Ok => {
                        self.backend.send(Request::List, Intent::Refresh);
                    }
                }
            }
            _ => {}
        }
        cx.notify();
    }
    fn start_edit(&mut self, id: TunnelId, cx: &mut Context<Self>) {
        self.send(Request::Get { id }, Intent::Edit, cx);
    }
    fn save(&mut self, cx: &mut Context<Self>) {
        let Some(editor) = &mut self.editor else {
            return;
        };
        editor.submitted = true;
        let values = editor.values(cx);
        if let Ok((config, preshared_keys)) = form::build(
            &editor.tunnel.config,
            &values,
            editor.peers,
            editor.all_traffic,
        ) {
            let request = Request::Save {
                id: editor.tunnel.id.clone(),
                name: values
                    .get("name")
                    .cloned()
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
                config,
                preshared_keys,
            };
            self.send(request, Intent::SaveConnect, cx);
        } else {
            cx.notify();
        }
    }
    fn add_peer(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(editor) = &self.editor else {
            return;
        };
        let index = editor.peers;
        let mut new = Vec::new();
        for field in ["endpoint", "public_key", "routes", "keepalive", "psk"] {
            let (input, sub) = self.input(String::new(), field == "psk", window, cx);
            new.push((form::key(index, field), input, sub));
        }
        let editor = self.editor.as_mut().unwrap();
        editor.peers += 1;
        for (key, input, sub) in new {
            editor.fields.insert(key, input);
            editor._subscriptions.push(sub);
        }
        cx.notify();
    }
    fn open_import(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(tr("import_file")),
        });
        cx.spawn_in(window, async move |this, cx| match receiver.await {
            Ok(Ok(Some(paths))) => {
                if let Some(path) = paths.first() {
                    let path = path.clone();
                    let _ = this.update(cx, |this, cx| {
                        this.busy = true;
                        this.backend.command(Command::ImportFile(path));
                        cx.notify();
                    });
                }
            }
            Ok(Ok(None)) => {}
            _ => {
                let _ = this.update(cx, |this, cx| {
                    this.notice = Some(tr("import_read_error"));
                    cx.notify();
                });
            }
        })
        .detach();
    }
    fn paste(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        if let Some(clipboard) = cx.read_from_clipboard()
            && self.paste_item(&clipboard, cx)
        {
            return;
        }
        self.notice = Some(tr("clipboard_empty"));
        cx.notify();
    }
    fn paste_item(&mut self, clipboard: &ClipboardItem, cx: &mut Context<Self>) -> bool {
        if self.busy {
            return true;
        }
        let command = if let Some(text) = clipboard
            .text()
            .map(SensitiveText::new)
            .filter(|s| s.expose().contains("[Interface]"))
        {
            if text.expose().len() > wge_config::MAX_CONFIG_BYTES {
                self.notice = Some(tr("import_too_large"));
                cx.notify();
                return true;
            }
            Command::ImportText(text)
        } else if let Some(image) = clipboard.entries().iter().find_map(|entry| {
            if let ClipboardEntry::Image(image) = entry {
                Some(image)
            } else {
                None
            }
        }) {
            Command::ImportImage(zeroize::Zeroizing::new(image.bytes().to_vec()))
        } else {
            return false;
        };
        self.busy = true;
        self.notice = None;
        self.backend.command(command);
        cx.notify();
        true
    }
    fn export(&mut self, id: TunnelId, name: String, window: &mut Window, cx: &mut Context<Self>) {
        self.confirmation = None;
        let name: String = name
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_'))
            .collect();
        let filename = format!("{}.conf", if name.is_empty() { "tunnel" } else { &name });
        let dir = directories::UserDirs::new()
            .and_then(|d| d.download_dir().map(std::path::Path::to_owned))
            .unwrap_or_default();
        let receiver = cx.prompt_for_new_path(&dir, Some(&filename));
        cx.spawn_in(window, async move |this, cx| match receiver.await {
            Ok(Ok(Some(path))) => {
                let _ = this.update(cx, |this, cx| {
                    this.send(
                        Request::Export {
                            id,
                            confirmed: true,
                        },
                        Intent::Export(path),
                        cx,
                    )
                });
            }
            Ok(Ok(None)) => {}
            _ => {
                let _ = this.update(cx, |this, cx| {
                    this.notice = Some(tr("export_write_error"));
                    cx.notify();
                });
            }
        })
        .detach();
        cx.notify();
    }
    fn sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .w(px(196.))
            .h_full()
            .flex_shrink_0()
            .bg(rgb(0xf0f3ee))
            .border_r_1()
            .border_color(rgb(LINE))
            .p_5()
            .flex()
            .flex_col()
            .justify_between()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_8()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .py_3()
                            .child(
                                div()
                                    .size(px(34.))
                                    .rounded_lg()
                                    .bg(rgb(INK))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .text_color(rgb(0xffffff))
                                    .child(Icon::new(IconName::Waypoints).size(px(20.))),
                            )
                            .child(
                                div()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_lg()
                                    .child(tr("app_name")),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                Button::new("tunnels-nav")
                                    .w_full()
                                    .when(!self.show_settings, |b| b.primary())
                                    .label(tr("tunnels"))
                                    .disabled(self.busy)
                                    .icon(IconName::Waypoints)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.clear_secrets(window, cx);
                                        this.clear_editor();
                                        this.show_settings = false;
                                        this.confirmation = None;
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("settings-nav")
                                    .ghost()
                                    .w_full()
                                    .label(tr("settings"))
                                    .disabled(self.busy)
                                    .icon(IconName::Settings2)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.clear_secrets(window, cx);
                                        this.clear_editor();
                                        this.show_settings = true;
                                        this.confirmation = None;
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(div().h(px(1.)).bg(rgb(LINE)))
                    .child(small(tr("local_only")))
                    .child(small(tr("background_hint")))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .mt_3()
                            .child(small(format!("v{}", env!("CARGO_PKG_VERSION"))))
                            .child(
                                Button::new("language")
                                    .ghost()
                                    .small()
                                    .label(tr("language_name"))
                                    .disabled(self.busy)
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let languages = rust_i18n::available_locales!();
                                        let locale = rust_i18n::locale();
                                        let next = languages
                                            .iter()
                                            .position(|l| **l == *locale)
                                            .map(|i| (i + 1) % languages.len())
                                            .unwrap_or(0);
                                        rust_i18n::set_locale(&languages[next]);
                                        this.settings.language = Some(languages[next].to_string());
                                        this.backend.send(Request::List, Intent::Action);
                                        if this.settings.save().is_err() {
                                            this.notice = Some(tr("settings_write_error"));
                                        }
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
    }
    fn import_actions(&self, cx: &mut Context<Self>) -> Div {
        div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                Button::new("paste-import")
                    .ghost()
                    .small()
                    .icon(IconName::ClipboardPaste)
                    .label(tr("paste"))
                    .disabled(self.busy)
                    .on_click(cx.listener(|this, _, _, cx| this.paste(cx))),
            )
            .child(
                Button::new("screen-import")
                    .ghost()
                    .small()
                    .icon(IconName::ScanLine)
                    .label(tr("scan_screen"))
                    .disabled(self.busy)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.busy = true;
                        this.backend.command(Command::Scan);
                        cx.notify();
                    })),
            )
            .child(
                Button::new("file-import")
                    .outline()
                    .small()
                    .icon(IconName::Import)
                    .label(tr("import_file"))
                    .disabled(self.busy)
                    .on_click(cx.listener(|this, _, window, cx| this.open_import(window, cx))),
            )
    }
    fn tunnel_list(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tunnels: Vec<_> = self.snapshot.tunnels.iter().filter(|t| t.saved).collect();
        let count = tunnels.len();
        let mut list = div().flex().flex_col().gap_5();
        if tunnels.is_empty() {
            list = list.child(
                panel()
                    .py_12()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_4()
                    .child(
                        div()
                            .size(px(68.))
                            .rounded_full()
                            .bg(rgb(WASH))
                            .text_color(rgb(GREEN))
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(Icon::new(IconName::Waypoints).size(px(30.))),
                    )
                    .child(heading(tr("empty_title")))
                    .child(small(tr("empty_hint")))
                    .child(
                        Button::new("first-tunnel")
                            .primary()
                            .mt_3()
                            .icon(IconName::Plus)
                            .label(tr("add_tunnel"))
                            .disabled(self.busy || self.offline)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.send(Request::BeginDraft, Intent::Edit, cx)
                            })),
                    )
                    .child(small(tr("drop_hint"))),
            );
        } else {
            let mut rows = panel().p_0().overflow_hidden();
            for tunnel in tunnels {
                let id = tunnel.id.clone();
                let toggle_id = id.clone();
                let selected = self.selected.as_ref() == Some(&id);
                rows = rows.child(
                    div()
                        .id(SharedString::from(format!("row-{}", id.0)))
                        .p_5()
                        .flex()
                        .items_center()
                        .gap_4()
                        .border_b_1()
                        .border_color(rgb(LINE))
                        .when(selected, |d| d.bg(rgb(WASH)))
                        .child(
                            Button::new(SharedString::from(format!("select-{}", id.0)))
                                .ghost()
                                .icon(IconName::Waypoints)
                                .label(tunnel.name.clone())
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.selected = Some(id.clone());
                                    this.notice = None;
                                    cx.notify();
                                })),
                        )
                        .child(div().flex_1().min_w_0().child(small(
                            if tunnel.config.is_all_traffic() {
                                tr("all_traffic")
                            } else {
                                rust_i18n::t!(
                                    "ranges_count",
                                    count = tunnel.config.allowed_ips().count()
                                )
                                .into_owned()
                                .into()
                            },
                        )))
                        .child(if self.offline {
                            small(tr("status_unknown"))
                        } else {
                            status(tunnel.status.state)
                        })
                        .child(
                            Switch::new(SharedString::from(format!("toggle-{}", toggle_id.0)))
                                .checked(enabled(tunnel.status.state))
                                .disabled(self.busy || self.offline)
                                .accessibility_label(
                                    rust_i18n::t!("toggle_tunnel", name = tunnel.name.clone())
                                        .into_owned(),
                                )
                                .on_click(cx.listener(move |this, on, _, cx| {
                                    this.selected = Some(toggle_id.clone());
                                    this.send(
                                        if *on {
                                            Request::Connect {
                                                id: toggle_id.clone(),
                                            }
                                        } else {
                                            Request::Disconnect {
                                                id: toggle_id.clone(),
                                            }
                                        },
                                        Intent::Action,
                                        cx,
                                    );
                                })),
                        ),
                );
            }
            list = list.child(rows);
            if let Some(tunnel) = self
                .selected
                .as_ref()
                .and_then(|id| self.snapshot.tunnels.iter().find(|t| &t.id == id))
            {
                list = list.child(self.detail(tunnel, cx));
            }
        }
        div()
            .flex()
            .flex_col()
            .gap_7()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_4()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .text_3xl()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(tr("your_tunnels")),
                            )
                            .child(small(
                                rust_i18n::t!("tunnel_count", count = count).into_owned(),
                            )),
                    )
                    .child(
                        Button::new("new-tunnel")
                            .primary()
                            .icon(IconName::Plus)
                            .label(tr("add_tunnel"))
                            .disabled(self.busy || self.offline)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.send(Request::BeginDraft, Intent::Edit, cx)
                            })),
                    ),
            )
            .child(self.import_actions(cx))
            .child(list)
    }
    fn detail(&self, tunnel: &Tunnel, cx: &mut Context<Self>) -> AnyElement {
        let id = tunnel.id.clone();
        let export_id = id.clone();
        let delete_id = id.clone();
        let export_name = tunnel.name.clone();
        let delete_name = tunnel.name.clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last = tunnel
            .status
            .peers
            .iter()
            .filter_map(|p| p.last_handshake_unix)
            .max();
        let sent = tunnel.status.peers.iter().map(|p| p.tx_bytes).sum();
        let received = tunnel.status.peers.iter().map(|p| p.rx_bytes).sum();
        let endpoints = tunnel
            .config
            .peers
            .iter()
            .filter_map(|p| p.endpoint.as_ref().map(ToString::to_string))
            .collect::<Vec<_>>()
            .join(", ");
        let mut detail = panel()
            .flex()
            .flex_col()
            .gap_5()
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(heading(tunnel.name.clone()))
                    .child(
                        Button::new("edit-tunnel")
                            .ghost()
                            .label(tr("edit"))
                            .icon(IconName::Pencil)
                            .disabled(self.busy)
                            .on_click(
                                cx.listener(move |this, _, _, cx| this.start_edit(id.clone(), cx)),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap_8()
                    .child(metric(
                        "handshake",
                        last.map(|t| {
                            rust_i18n::t!("seconds_ago", seconds = now.saturating_sub(t))
                                .into_owned()
                        })
                        .unwrap_or_else(|| rust_i18n::t!("never").into_owned()),
                    ))
                    .child(metric("received", bytes(received)))
                    .child(metric("sent", bytes(sent))),
            )
            .child(metric("server_address", endpoints));
        if matches!(
            tunnel.status.state,
            ConnectionState::Connecting | ConnectionState::NoHandshake
        ) {
            detail = detail.child(
                div()
                    .p_4()
                    .rounded_lg()
                    .bg(rgb(0xfcf3e6))
                    .text_sm()
                    .text_color(rgb(0x805b30))
                    .child(tr("handshake_hint")),
            );
        }
        if let Some(error) = &tunnel.status.error {
            detail = detail.child(small(tr(error_key(error.code))));
        }
        detail
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_t_1()
                    .border_color(rgb(LINE))
                    .pt_4()
                    .child(
                        Button::new("export-tunnel")
                            .disabled(self.busy || self.offline)
                            .ghost()
                            .icon(IconName::Download)
                            .label(tr("export"))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.confirmation =
                                    Some(Confirm::Export(export_id.clone(), export_name.clone()));
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("delete-tunnel")
                            .disabled(self.busy || self.offline)
                            .ghost()
                            .icon(IconName::Trash)
                            .label(tr("delete"))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.confirmation =
                                    Some(Confirm::Delete(delete_id.clone(), delete_name.clone()));
                                cx.notify();
                            })),
                    ),
            )
            .into_any_element()
    }
    fn field(
        &self,
        id: &str,
        label: &str,
        hint: &str,
        errors: &form::Errors,
        cx: &Context<Self>,
    ) -> Div {
        let editor = self.editor.as_ref().unwrap();
        let input = &editor.fields[id];
        let show_error = editor.submitted || !input.read(cx).value().is_empty();
        let error = errors.get(id).filter(|_| show_error);
        let view = cx.entity().downgrade();
        div()
            .flex()
            .flex_col()
            .gap_1()
            .flex_1()
            .min_w_0()
            .child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::MEDIUM)
                    .child(tr(label)),
            )
            .child(
                Input::new(input)
                    .on_paste(move |clipboard, _, cx| {
                        view.update(cx, |view, cx| view.paste_item(clipboard, cx))
                            .unwrap_or(false)
                    })
                    .aria_label(tr(label))
                    .disabled(self.busy)
                    .w_full(),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(if error.is_some() { 0xa4483d } else { MUTED }))
                    .child(tr(error.copied().unwrap_or(hint))),
            )
    }
    fn editor_form(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let editor = self.editor.as_ref().unwrap();
        let values = editor.values(cx);
        let result = form::build(
            &editor.tunnel.config,
            &values,
            editor.peers,
            editor.all_traffic,
        );
        let errors = result.as_ref().err().cloned().unwrap_or_default();
        let title = if editor.tunnel.saved {
            "edit_tunnel"
        } else {
            "new_tunnel"
        };
        let id = editor.tunnel.id.clone();
        let public_key = editor.tunnel.config.interface.public_key.to_string();
        let copy_key = public_key.clone();
        let mut fields = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                panel().p_4().child(group("this_device", "01")).child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(
                            div()
                                .flex()
                                .gap_4()
                                .child(self.field("name", "tunnel_name", "hint_name", &errors, cx))
                                .child(self.field(
                                    "addresses",
                                    "tunnel_address",
                                    "hint_addresses",
                                    &errors,
                                    cx,
                                )),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .justify_between()
                                        .child(small(tr("your_public_key")))
                                        .child(
                                            Button::new("copy-public")
                                                .ghost()
                                                .small()
                                                .icon(IconName::Copy)
                                                .accessibility_label(tr("copy_public_key"))
                                                .on_click(move |_, _, cx| {
                                                    cx.write_to_clipboard(
                                                        ClipboardItem::new_string(copy_key.clone()),
                                                    )
                                                }),
                                        ),
                                )
                                .child(div().text_xs().font_family("monospace").child(public_key))
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(rgb(MUTED))
                                        .child(tr("hint_public_key")),
                                ),
                        ),
                ),
            )
            .child(
                panel().p_4().child(group("server", "02")).child(
                    div()
                        .flex()
                        .gap_4()
                        .child(self.field(
                            "0.endpoint",
                            "server_address",
                            "hint_endpoint",
                            &errors,
                            cx,
                        ))
                        .child(self.field(
                            "0.public_key",
                            "server_public_key",
                            "hint_server_key",
                            &errors,
                            cx,
                        )),
                ),
            )
            .child(
                panel().p_4().child(group("traffic", "03")).child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(
                            div()
                                .flex()
                                .justify_between()
                                .items_center()
                                .gap_4()
                                .child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(
                                            div()
                                                .text_sm()
                                                .font_weight(FontWeight::MEDIUM)
                                                .child(tr("all_traffic")),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(rgb(MUTED))
                                                .child(tr("hint_all_traffic")),
                                        ),
                                )
                                .child(
                                    Switch::new("all-traffic")
                                        .disabled(self.busy)
                                        .checked(editor.all_traffic)
                                        .accessibility_label(tr("all_traffic"))
                                        .on_click(cx.listener(|this, on, _, cx| {
                                            if let Some(editor) = &mut this.editor {
                                                editor.all_traffic = *on;
                                            }
                                            cx.notify();
                                        })),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_4()
                                .when(!editor.all_traffic, |d| {
                                    d.child(self.field(
                                        "0.routes",
                                        "traffic_ranges",
                                        "hint_routes",
                                        &errors,
                                        cx,
                                    ))
                                })
                                .child(self.field("dns", "dns_servers", "hint_dns", &errors, cx)),
                        ),
                ),
            );
        let advanced = editor.advanced;
        fields = fields.child(
            Button::new("advanced")
                .ghost()
                .icon(if advanced {
                    IconName::ChevronUp
                } else {
                    IconName::ChevronDown
                })
                .label(tr("advanced"))
                .disabled(self.busy)
                .on_click(cx.listener(|this, _, _, cx| {
                    if let Some(editor) = &mut this.editor {
                        editor.advanced = !editor.advanced;
                    }
                    cx.notify();
                })),
        );
        if advanced {
            let revealed = editor.revealed.is_some();
            let reveal_id = id.clone();
            let generation = editor.generation;
            let mut advanced = panel()
                .flex()
                .flex_col()
                .gap_5()
                .child(
                    self.field(
                        "0.psk",
                        "preshared_key",
                        if editor
                            .tunnel
                            .config
                            .peers
                            .first()
                            .is_some_and(|p| p.has_preshared_key)
                        {
                            "hint_psk_set"
                        } else {
                            "hint_psk"
                        },
                        &errors,
                        cx,
                    ),
                )
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(self.field(
                            "0.keepalive",
                            "keepalive",
                            "hint_keepalive",
                            &errors,
                            cx,
                        ))
                        .child(self.field("mtu", "mtu", "hint_mtu", &errors, cx)),
                )
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(self.field("port", "listen_port", "hint_port", &errors, cx))
                        .child(self.field("domains", "dns_domains", "hint_domains", &errors, cx)),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(small(tr("private_key")))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_3()
                                .child(
                                    div()
                                        .flex_1()
                                        .text_xs()
                                        .font_family("monospace")
                                        .overflow_hidden()
                                        .child(
                                            editor
                                                .revealed
                                                .as_ref()
                                                .map(|s| s.expose().to_owned())
                                                .unwrap_or_else(|| {
                                                    "•••• •••• •••• •••• •••• ••••".to_owned()
                                                }),
                                        ),
                                )
                                .child(
                                    Button::new("show-private")
                                        .ghost()
                                        .small()
                                        .label(tr(if revealed { "hide" } else { "show" }))
                                        .disabled(self.busy)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            if let Some(editor) = &mut this.editor
                                                && editor.revealed.take().is_some()
                                            {
                                                cx.notify();
                                                return;
                                            }
                                            this.send(
                                                Request::RevealPrivateKey {
                                                    id: reveal_id.clone(),
                                                },
                                                Intent::Reveal(reveal_id.clone(), generation),
                                                cx,
                                            );
                                        })),
                                ),
                        )
                        .child(small(tr("hint_private_key"))),
                );
            for index in 1..editor.peers {
                let mut peer = div()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .pt_5()
                    .border_t_1()
                    .border_color(rgb(LINE))
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(rust_i18n::t!("extra_peer", number = index + 1).into_owned()),
                    )
                    .child(self.field(
                        &form::key(index, "endpoint"),
                        "server_address",
                        "hint_extra_endpoint",
                        &errors,
                        cx,
                    ))
                    .child(self.field(
                        &form::key(index, "public_key"),
                        "server_public_key",
                        "hint_server_key",
                        &errors,
                        cx,
                    ))
                    .child(self.field(
                        &form::key(index, "routes"),
                        "traffic_ranges",
                        "hint_routes",
                        &errors,
                        cx,
                    ))
                    .child(self.field(
                        &form::key(index, "psk"),
                        "preshared_key",
                        "hint_psk",
                        &errors,
                        cx,
                    ))
                    .child(self.field(
                        &form::key(index, "keepalive"),
                        "keepalive",
                        "hint_keepalive",
                        &errors,
                        cx,
                    ));
                if index == editor.peers - 1 {
                    peer = peer.child(
                        Button::new(SharedString::from(format!("remove-peer-{index}")))
                            .ghost()
                            .small()
                            .label(tr("remove_peer"))
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                if let Some(editor) = &mut this.editor {
                                    editor.peers -= 1;
                                    if let Some(input) =
                                        editor.fields.get(&form::key(editor.peers, "psk"))
                                    {
                                        input.update(cx, |input, cx| {
                                            input.set_value("", window, cx)
                                        });
                                    }
                                    let prefix = format!("{}.", editor.peers);
                                    editor.fields.retain(|k, _| !k.starts_with(&prefix));
                                }
                                cx.notify();
                            })),
                    );
                }
                advanced = advanced.child(peer);
            }
            fields = fields.child(
                advanced.child(
                    Button::new("add-peer")
                        .outline()
                        .icon(IconName::Plus)
                        .label(tr("add_peer"))
                        .disabled(self.busy)
                        .on_click(cx.listener(|this, _, window, cx| this.add_peer(window, cx))),
                ),
            );
        }
        let preview = self.preview(&values, cx);
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .h_full()
            .gap_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .flex_shrink_0()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_2xl()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(tr(title)),
                            )
                            .child(small(tr("setup_hint"))),
                    )
                    .child(
                        Button::new("cancel-editor")
                            .disabled(self.busy)
                            .ghost()
                            .label(tr("cancel"))
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.clear_secrets(window, cx);
                                this.clear_editor();
                                cx.notify();
                            })),
                    ),
            )
            .child(self.import_actions(cx).flex_shrink_0())
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .gap_4()
                    .child(
                        div()
                            .id("editor-fields")
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .child(fields)
                            .overflow_y_scrollbar(),
                    )
                    .child(
                        div()
                            .id("preview-scroll")
                            .w(px(280.))
                            .flex_shrink_0()
                            .h_full()
                            .child(preview)
                            .overflow_y_scrollbar(),
                    ),
            )
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .flex_shrink_0()
                    .border_t_1()
                    .border_color(rgb(LINE))
                    .pt_4()
                    .gap_4()
                    .child(small(tr("save_hint")))
                    .child(
                        Button::new("save-connect")
                            .primary()
                            .icon(IconName::ArrowRight)
                            .label(tr(if self.busy { "saving" } else { "save_connect" }))
                            .disabled(self.busy || self.offline)
                            .on_click(cx.listener(|this, _, _, cx| this.save(cx))),
                    ),
            )
            .into_any_element()
    }
    fn preview(&mut self, values: &form::Values, cx: &App) -> AnyElement {
        let editor = self.editor.as_mut().unwrap();
        let mut preview_config = editor.tunnel.config.clone();
        preview_config.interface.addresses = form::split(
            values
                .get("addresses")
                .map(|value| value.as_str())
                .unwrap_or(""),
        )
        .filter_map(|v| v.parse().ok())
        .collect();
        let snippet = wge_config::server_snippet(&preview_config);
        if editor.qr.as_ref().is_none_or(|(old, _)| old != &snippet) {
            editor.qr = crate::import::qr_png(&snippet).map(|png| {
                (
                    snippet.clone(),
                    Arc::new(Image::from_bytes(ImageFormat::Png, png)),
                )
            });
        }
        let mut ranges = Vec::new();
        for index in 0..editor.peers {
            let value = if index == 0 && editor.all_traffic {
                "0.0.0.0/0, ::/0"
            } else {
                values
                    .get(&form::key(index, "routes"))
                    .map(|value| value.as_str())
                    .unwrap_or("")
            };
            ranges
                .extend(form::split(value).filter_map(|v| v.parse::<wge_config::IpNetwork>().ok()));
        }
        let endpoint = values
            .get("0.endpoint")
            .filter(|v| !v.is_empty())
            .map(|value| value.to_string())
            .unwrap_or_else(|| rust_i18n::t!("your_server").into_owned());
        let mut preview = panel()
            .w_full()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap_5()
            .child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(tr("live_preview")),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_2()
                    .py_3()
                    .child(
                        Icon::new(IconName::Laptop)
                            .size(px(28.))
                            .text_color(rgb(INK)),
                    )
                    .child(div().text_sm().child(tr("this_computer")))
                    .child(div().w(px(1.)).h(px(22.)).bg(rgb(GREEN)))
                    .child(
                        div()
                            .rounded_full()
                            .bg(rgb(WASH))
                            .px_4()
                            .py_2()
                            .text_xs()
                            .text_color(rgb(GREEN))
                            .child(tr(if editor.all_traffic {
                                "encrypted_all"
                            } else {
                                "encrypted_ranges"
                            })),
                    )
                    .child(div().w(px(1.)).h(px(22.)).bg(rgb(GREEN)))
                    .child(
                        Icon::new(IconName::Server)
                            .size(px(28.))
                            .text_color(rgb(INK)),
                    )
                    .child(div().text_xs().text_center().child(endpoint)),
            )
            .child(div().h(px(1.)).bg(rgb(LINE)))
            .child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::MEDIUM)
                    .child(tr("range_coverage")),
            );
        if ranges.is_empty() {
            preview = preview.child(small(tr("range_empty")));
        }
        for range in ranges.iter() {
            let coverage = wge_config::coverage(range);
            preview = preview.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_xs()
                            .font_family("monospace")
                            .child(range.to_string()),
                    )
                    .child(
                        div().text_xs().text_color(rgb(MUTED)).child(
                            rust_i18n::t!(
                                "range_description",
                                first = coverage.first,
                                last = coverage.last,
                                count = coverage.address_count
                            )
                            .into_owned(),
                        ),
                    ),
            );
        }
        for tunnel in self
            .snapshot
            .tunnels
            .iter()
            .filter(|t| t.id != editor.tunnel.id)
        {
            let other: Vec<_> = tunnel.config.allowed_ips().copied().collect();
            if !wge_config::route_overlaps(&ranges, &other).is_empty() {
                preview = preview.child(warning(
                    rust_i18n::t!("overlap_tunnel", name = tunnel.name.clone()).into_owned(),
                ));
            }
        }
        if ranges.iter().any(|r| {
            r.prefix() != 0
                && self
                    .snapshot
                    .local_networks
                    .iter()
                    .any(|local| wge_config::overlaps(r, local))
        }) {
            preview = preview.child(warning(rust_i18n::t!("overlap_local").into_owned()));
        }
        let copy_snippet = snippet.clone();
        preview = preview
            .child(div().h(px(1.)).bg(rgb(LINE)))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::MEDIUM)
                            .child(tr("server_snippet")),
                    )
                    .child(
                        Button::new("copy-snippet")
                            .ghost()
                            .small()
                            .icon(IconName::Copy)
                            .accessibility_label(tr("copy_snippet"))
                            .on_click(move |_, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(
                                    copy_snippet.clone(),
                                ))
                            }),
                    ),
            )
            .child(small(tr("snippet_hint")))
            .child(
                div()
                    .text_xs()
                    .font_family("monospace")
                    .bg(rgb(PAPER))
                    .p_3()
                    .rounded_lg()
                    .overflow_hidden()
                    .child(snippet),
            );
        if let Some((_, qr)) = &editor.qr {
            preview = preview.child(
                div()
                    .flex()
                    .justify_center()
                    .child(img(qr.clone()).size(px(176.))),
            );
        }
        let _ = cx;
        preview.into_any_element()
    }
    fn settings_view(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut languages = div().flex().gap_3();
        for locale in rust_i18n::available_locales!() {
            let selected = *locale == *rust_i18n::locale();
            languages = languages.child(
                Button::new(SharedString::from(format!("language-{locale}")))
                    .when(selected, |b| b.primary())
                    .label(rust_i18n::t!("language_name", locale = locale).into_owned())
                    .on_click(cx.listener(move |this, _, _, cx| {
                        rust_i18n::set_locale(&locale);
                        this.settings.language = Some(locale.to_string());
                        this.backend.send(Request::List, Intent::Action);
                        if this.settings.save().is_err() {
                            this.notice = Some(tr("settings_write_error"));
                        }
                        cx.notify();
                    })),
            );
        }
        div()
            .flex()
            .flex_col()
            .gap_7()
            .child(
                div()
                    .text_3xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(tr("settings")),
            )
            .child(
                panel()
                    .flex()
                    .flex_col()
                    .gap_5()
                    .child(heading(tr("language")))
                    .child(small(tr("language_hint")))
                    .child(languages),
            )
            .child(
                panel()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_5()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(heading(tr("start_at_login")))
                            .child(small(tr("login_hint"))),
                    )
                    .child(
                        Switch::new("start-at-login")
                            .checked(self.settings.start_at_login)
                            .accessibility_label(tr("start_at_login"))
                            .on_click(cx.listener(|this, on, _, cx| {
                                if this.settings.set_login(*on).is_err() {
                                    this.notice = Some(tr("settings_write_error"));
                                }
                                cx.notify();
                            })),
                    ),
            )
            .child(
                panel()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(heading(tr("about")))
                    .child(small(tr("about_hint")))
                    .child(small(tr("no_accounts")))
                    .child(
                        Button::new("quit")
                            .outline()
                            .label(tr("quit_app"))
                            .on_click(|_, _, cx| cx.quit()),
                    ),
            )
            .into_any_element()
    }
    fn confirmation_view(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let confirmation = self.confirmation.as_ref()?;
        let (id, name, export) = match confirmation {
            Confirm::Export(id, name) => (id.clone(), name.clone(), true),
            Confirm::Delete(id, name) => (id.clone(), name.clone(), false),
        };
        Some(
            div()
                .p_5()
                .rounded_xl()
                .border_1()
                .border_color(rgb(0xdfbd8b))
                .bg(rgb(0xfff7eb))
                .flex()
                .flex_col()
                .gap_4()
                .child(heading(
                    rust_i18n::t!(
                        if export {
                            "export_title"
                        } else {
                            "delete_title"
                        },
                        name = name.clone()
                    )
                    .into_owned(),
                ))
                .child(small(tr(if export {
                    "export_confirmation"
                } else {
                    "delete_confirmation"
                })))
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .child(
                            Button::new("confirm-cancel")
                                .outline()
                                .label(tr("cancel"))
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.confirmation = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("confirm-action")
                                .disabled(self.busy || self.offline)
                                .primary()
                                .label(tr(if export { "export_confirm" } else { "delete" }))
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    if export {
                                        this.export(id.clone(), name.clone(), window, cx);
                                    } else {
                                        this.confirmation = None;
                                        this.selected = None;
                                        this.send(
                                            Request::Delete { id: id.clone() },
                                            Intent::Action,
                                            cx,
                                        );
                                    }
                                })),
                        ),
                )
                .into_any_element(),
        )
    }
}
impl Drop for MainView {
    fn drop(&mut self) {
        self.clear_editor();
    }
}
impl Focusable for MainView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}
impl Render for MainView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = if self.editor.is_some() {
            self.editor_form(cx)
        } else if self.show_settings {
            self.settings_view(cx)
        } else {
            self.tunnel_list(cx).into_any_element()
        };
        let confirmation = self.confirmation_view(cx);
        let editing = self.editor.is_some();
        div()
            .id("desktop")
            .track_focus(&self.focus)
            .size_full()
            .bg(rgb(PAPER))
            .text_color(rgb(INK))
            .text_base()
            .flex()
            .on_drop(cx.listener(|this, paths: &ExternalPaths, _, cx| {
                if this.busy {
                    return;
                }
                if let Some(path) = paths.0.first() {
                    this.busy = true;
                    this.backend.command(Command::ImportFile(path.clone()));
                    cx.notify();
                }
            }))
            .capture_key_down(cx.listener(|this, event: &KeyDownEvent, _, cx| {
                if event.keystroke.key == "v"
                    && (event.keystroke.modifiers.control || event.keystroke.modifiers.platform)
                    && let Some(clipboard) = cx.read_from_clipboard()
                    && this.paste_item(&clipboard, cx)
                {
                    cx.stop_propagation();
                }
            }))
            .child(self.sidebar(cx))
            .child(
                div()
                    .id("content-scroll")
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .when(editing, |d| d.overflow_hidden())
                    .when(!editing, |d| d.overflow_y_scroll())
                    .p_6()
                    .child(
                        div()
                            .w_full()
                            .max_w(px(1140.))
                            .when(editing, |d| d.h_full().min_h_0())
                            .mx_auto()
                            .flex()
                            .flex_col()
                            .gap_5()
                            .when(self.offline, |d| {
                                d.child(warning(rust_i18n::t!("service_offline").into_owned()))
                            })
                            .when_some(self.notice.clone(), |d, notice| {
                                d.child(
                                    div()
                                        .p_4()
                                        .rounded_lg()
                                        .border_1()
                                        .border_color(rgb(LINE))
                                        .bg(rgb(0xffffff))
                                        .text_sm()
                                        .child(notice),
                                )
                            })
                            .when_some(confirmation, |d, confirmation| d.child(confirmation))
                            .child(content),
                    ),
            )
    }
}
fn metric(label: &str, value: String) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(small(tr(label)))
        .child(div().text_sm().font_weight(FontWeight::MEDIUM).child(value))
}
fn warning(message: String) -> Div {
    div()
        .p_3()
        .rounded_lg()
        .bg(rgb(0xfcf3e6))
        .text_xs()
        .text_color(rgb(0x805b30))
        .child(message)
}
fn error_key(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Validation => "api_validation",
        ErrorCode::NotFound => "api_not_found",
        ErrorCode::Conflict => "api_conflict",
        ErrorCode::Unauthorized => "api_unauthorized",
        ErrorCode::Busy => "api_busy",
        ErrorCode::Network => "api_network",
        ErrorCode::Protocol => "api_protocol",
        ErrorCode::Internal => "api_internal",
        ErrorCode::Endpoint => "api_endpoint",
        ErrorCode::Dns => "api_dns",
        ErrorCode::Permission => "api_permission",
        ErrorCode::Driver => "api_driver",
        ErrorCode::Recovery => "api_recovery",
        ErrorCode::ScriptHook => "api_script_hook",
        ErrorCode::UnsupportedConfig => "api_unsupported_config",
    }
}

#[cfg(test)]
impl MainView {
    #[allow(dead_code)]
    pub fn check_preshared_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let editor = self.editor.as_ref().unwrap();
        editor.fields["0.psk"].update(cx, |input, cx| input.set_value(key, window, cx));
        let values = editor.values(cx);
        let (config, secrets) = form::build(
            &editor.tunnel.config,
            &values,
            editor.peers,
            editor.all_traffic,
        )
        .unwrap();
        assert!(config.peers[0].has_preshared_key);
        assert!(
            secrets[0]
                .value
                .as_ref()
                .is_some_and(|value| value.expose() == key)
        );
        self.clear_secrets(window, cx);
        assert!(
            self.editor.as_ref().unwrap().fields["0.psk"]
                .read(cx)
                .text()
                .len()
                == 0
        );
    }
    #[allow(dead_code)]
    pub fn check_clipboard_imports(
        &mut self,
        commands: &mut tokio::sync::mpsc::UnboundedReceiver<Command>,
        config: &str,
        cx: &mut Context<Self>,
    ) {
        let previous = cx.read_from_clipboard();
        cx.write_to_clipboard(ClipboardItem::new_string(config.into()));
        self.paste(cx);
        assert!(
            matches!(commands.try_recv(), Ok(Command::ImportText(text)) if text.expose() == config)
        );
        self.busy = false;
        let image = Image::from_bytes(ImageFormat::Png, crate::import::qr_png(config).unwrap());
        cx.write_to_clipboard(ClipboardItem::new_image(&image));
        self.paste(cx);
        assert!(
            matches!(commands.try_recv(), Ok(Command::ImportImage(bytes))
            if crate::import::decode_image(&bytes).is_ok_and(|text| text.expose() == config))
        );
        self.busy = false;
        cx.write_to_clipboard(ClipboardItem::new_string(format!(
            "[Interface]\n{}",
            " ".repeat(wge_config::MAX_CONFIG_BYTES)
        )));
        self.paste(cx);
        assert!(commands.try_recv().is_err());
        assert!(!self.busy);
        assert_eq!(self.notice, Some(tr("import_too_large")));
        assert!(!self.paste_item(&ClipboardItem::new_string("ordinary field text".into()), cx));
        cx.write_to_clipboard(previous.unwrap_or_else(|| ClipboardItem::new_string(String::new())));
        self.notice = None;
    }
    #[allow(dead_code)]
    pub fn check_stale_reveal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let previous = self.editor.as_ref().expect("editor is open");
        let generation = previous.generation;
        let tunnel = previous.tunnel.clone();
        let id = tunnel.id.clone();
        self.edit(tunnel.clone(), window, cx);
        let mut reopened = Self::new(
            self.backend.clone(),
            self.snapshot.clone(),
            self.settings.clone(),
            false,
            cx,
        );
        reopened.edit(tunnel, window, cx);
        assert_ne!(reopened.editor.as_ref().unwrap().generation, generation);
        self.event(
            Event::Reply(
                Intent::Reveal(id, generation),
                Response::Secret(SensitiveText::new("private fixture".into())),
            ),
            window,
            cx,
        );
        assert!(self.editor.as_ref().unwrap().revealed.is_none());
    }
    #[allow(dead_code)]
    pub fn check_japanese_composition(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let editor = self.editor.as_ref().expect("editor is open");
        editor.fields["name"].update(cx, |input, cx| {
            input.set_value("", window, cx);
            input.replace_and_mark_text_in_range(None, "じたく", Some(3..3), window, cx);
            assert!(input.marked_text_range(window, cx).is_some());
            input.replace_and_mark_text_in_range(None, "自宅", Some(2..2), window, cx);
            input.replace_text_in_range(None, "自宅", window, cx);
            input.unmark_text(window, cx);
            assert_eq!(input.value().as_ref(), "自宅");
            assert!(input.marked_text_range(window, cx).is_none());
        });
        cx.notify();
    }
}

//! Explicit native acceptance harness. Synthetic public data never enters the app.
#![forbid(unsafe_code)]
#![allow(dead_code, unused_imports)]
#[path = "../src/appearance.rs"]
mod appearance;
#[path = "../src/backend.rs"]
mod backend;
#[path = "../src/focus_scroll.rs"]
mod focus_scroll;
#[path = "../src/form.rs"]
mod form;
#[path = "../src/import.rs"]
mod import;
#[path = "../src/settings.rs"]
mod settings;
#[path = "../src/tray.rs"]
mod tray;
#[path = "../src/ui.rs"]
mod ui;
use gpui_kit::*;

use std::{path::PathBuf, sync::Arc, time::Duration};
use wge_ipc::{ConnectionState, PeerStatus, Response, Snapshot, Tunnel, TunnelId, TunnelStatus};
rust_i18n::i18n!("locales", fallback = "en");

const CONFIG: &str = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.8.0.2/32, fd00:8::2/128\nDNS = 10.8.0.1\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.8.0.0/24, fd00:8::/64\nPersistentKeepalive = 25\n";

fn fixture() -> Tunnel {
    let config = wge_config::parse(CONFIG).unwrap().public();
    let peer = PeerStatus {
        public_key: config.peers[0].public_key,
        last_handshake_unix: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 12,
        ),
        rx_bytes: 15480933,
        tx_bytes: 2938550,
        endpoint: Some("vpn.example.com:51820".into()),
    };
    Tunnel {
        id: TunnelId("0123456789abcdef0123456789abcdef".into()),
        name: "Home network".into(),
        config,
        status: TunnelStatus {
            state: ConnectionState::Connected,
            peers: vec![peer],
            error: None,
        },
        saved: true,
    }
}
fn screenshot(directory: &std::path::Path, name: &str) {
    if std::env::var_os("WGE_PREVIEW_HEADLESS").is_some() {
        xcap::Monitor::all().expect("enumerate virtual monitors")[0]
            .capture_image()
            .expect("capture isolated virtual desktop")
            .save(directory.join(name))
            .expect("write capture");
        return;
    }
    let window = xcap::Window::all()
        .expect("enumerate windows")
        .into_iter()
        .find(|w| w.pid().ok() == Some(std::process::id()))
        .expect("native app window");
    window
        .capture_image()
        .expect("capture native window")
        .save(directory.join(name))
        .expect("write capture");
}
#[cfg(target_os = "linux")]
fn record_memory(directory: &std::path::Path, name: &str) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    println!(
        "{name}: {}",
        status
            .lines()
            .find(|line| line.starts_with("VmRSS:"))
            .unwrap()
    );
    std::fs::write(directory.join(name), status).unwrap();
}
struct Empty;
impl Render for Empty {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
    }
}

struct QrScan(Arc<Image>);
impl Render for QrScan {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .bg(rgb(0xffffff))
            .flex()
            .items_center()
            .justify_center()
            .child(img(self.0.clone()).size(px(480.)))
    }
}

fn key(stroke: &str, window: &mut Window, cx: &mut App) {
    let keystroke = Keystroke::parse(stroke).unwrap();
    window.dispatch_event(
        PlatformInput::KeyDown(KeyDownEvent {
            keystroke: keystroke.clone(),
            is_held: false,
            prefer_character_input: false,
        }),
        cx,
    );
    window.dispatch_event(PlatformInput::KeyUp(KeyUpEvent { keystroke }), cx);
}

fn main() {
    let Some(directory) = std::env::var_os("WGE_PREVIEW_DIR").map(PathBuf::from) else {
        return;
    };
    std::fs::create_dir_all(&directory).unwrap();
    let tunnel = fixture();
    let other = Tunnel {
        id: TunnelId("1123456789abcdef0123456789abcdef".into()),
        name: "Studio".into(),
        status: TunnelStatus::default(),
        ..tunnel.clone()
    };
    let snapshot = Snapshot {
        tunnels: vec![tunnel.clone(), other],
        local_networks: vec!["192.168.1.0/24".parse().unwrap()],
        ..Snapshot::default()
    };
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    gpui_kit::application()
        .with_quit_mode(QuitMode::Explicit)
        .with_assets(appearance::Assets)
        .run(move |cx| {
            appearance::init(cx);
            assert_eq!(gpui_kit::component::_rust_i18n_translate("ja", "Input.Copy"), "コピー");
            let (empty, _) = gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::centered(size(px(1280.), px(800.)), cx)),
                    ..Default::default()
                },
                cx,
                |_, cx| cx.new(|_| Empty),
            )
            .unwrap();
            cx.spawn(async move |cx| {
                cx.background_executor().timer(Duration::from_secs(2)).await;
                #[cfg(target_os = "linux")]
                record_memory(&directory, "empty-window-memory.txt");
                empty
                    .update(cx, |_, window, _| window.remove_window())
                    .unwrap();
                let (window, view) = cx.update(|cx| {
                    let (window, view) = gpui_kit::open_window(
                        WindowOptions {
                            window_bounds: Some(WindowBounds::centered(
                                size(px(1280.), px(800.)),
                                cx,
                            )),
                            titlebar: Some(TitlebarOptions {
                                title: Some("wg-easy · native acceptance".into()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        cx,
                        |_, cx| {
                            cx.new(|cx| {
                                ui::MainView::new(
                                    backend::Backend(sender),
                                    snapshot,
                                    settings::Settings::default(),
                                    false,
                                    cx,
                                )
                            })
                        },
                    )
                    .unwrap();
                    cx.activate(true);
                    (window, view)
                });

                cx.background_executor().timer(Duration::from_secs(2)).await;
                screenshot(&directory, "01-tunnels.png");
                #[cfg(target_os = "linux")]
                record_memory(&directory, "desktop-memory.txt");
                window
                    .update(cx, |_, window, cx| {
                        view.update(cx, |view, cx| {
                            view.event(
                                backend::Event::Reply(
                                    backend::Intent::Edit,
                                    Response::Tunnel(tunnel),
                                ),
                                window,
                                cx,
                            )
                        })
                    })
                    .unwrap();
                cx.background_executor().timer(Duration::from_secs(2)).await;
                screenshot(&directory, "02-editor.png");
                window.update(cx, |_, window, cx| {
                        view.read(cx).field_focus("0.public_key", cx).focus(window, cx);
                    key("tab", window, cx);
                    key("space", window, cx);
                    assert_eq!(view.read(cx).editor_modes(), (true, false));
                    key("space", window, cx);
                        view.read(cx).field_focus("dns", cx).focus(window, cx);
                    key("tab", window, cx);
                    key("enter", window, cx);
                    assert_eq!(view.read(cx).editor_modes(), (false, true));
                }).unwrap();
                cx.background_executor().timer(Duration::from_millis(200)).await;
                window.update(cx, |_, window, cx| key("tab", window, cx)).unwrap();
                cx.background_executor().timer(Duration::from_millis(200)).await;
                window.update(cx, |_, window, cx| view.read(cx).assert_visible_field("0.psk", window, cx)).unwrap();
                for _ in 0..4 {
                    window.update(cx, |_, window, cx| key("tab", window, cx)).unwrap();
                    cx.background_executor().timer(Duration::from_millis(100)).await;
                }
                window.update(cx, |_, window, cx| view.read(cx).assert_visible_field("domains", window, cx)).unwrap();
                window.update(cx, |_, window, cx| view.read(cx).reset_editor_scroll(window)).unwrap();
                cx.background_executor().timer(Duration::from_millis(200)).await;
                cx.update(|cx| view.read(cx).assert_editor_at_top());
                for _ in 0..3 {
                    window.update(cx, |_, window, cx| key("tab", window, cx)).unwrap();
                    cx.background_executor().timer(Duration::from_millis(100)).await;
                }
                window.update(cx, |_, window, cx| {
                    view.read(cx).assert_preview_scrolled();
                    let previous = cx.read_from_clipboard();
                    key("enter", window, cx);
                    assert!(cx.read_from_clipboard().and_then(|item| item.text()).is_some_and(|text| text.starts_with("[Peer]")));
                    cx.write_to_clipboard(previous.unwrap_or_else(|| ClipboardItem::new_string(String::new())));
                }).unwrap();
                window
                    .update(cx, |_, window, cx| {
                        view.update(cx, |view, cx| {
                            view.check_service_actions(&mut receiver, window, cx);
                            view.check_preshared_input(window, cx);
                            view.check_clipboard_imports(&mut receiver, CONFIG, cx);
                            view.check_stale_reveal(window, cx);
                            view.check_japanese_composition(window, cx);
                        })
                    })
                    .unwrap();
                cx.update(|cx| {
                    rust_i18n::set_locale("ja");
                    view.update(cx, |_, cx| cx.notify());
                });
                cx.background_executor().timer(Duration::from_secs(2)).await;
                screenshot(&directory, "03-japanese.png");
                window
                    .update(cx, |_, window, _| window.resize(size(px(1120.), px(800.))))
                    .unwrap();
                cx.background_executor().timer(Duration::from_secs(2)).await;
                screenshot(&directory, "04-compact-japanese.png");
                let (qr_window, _) = cx.update(|cx| {
                    gpui_kit::open_window(
                        WindowOptions {
                            window_bounds: Some(WindowBounds::centered(size(px(560.), px(560.)), cx)),
                            ..Default::default()
                        },
                        cx,
                        |_, cx| cx.new(|_| QrScan(Arc::new(Image::from_bytes(ImageFormat::Png, import::qr_png(CONFIG).unwrap())))),
                    ).unwrap()
                });
                cx.background_executor().timer(Duration::from_secs(2)).await;
                assert!(import::screen().is_ok_and(|text| text.expose() == CONFIG));
                qr_window.update(cx, |_, window, _| window.remove_window()).unwrap();
                println!("Native desktop checks passed: English/Japanese, keyboard navigation, edit/save/connect/delete handlers, peer removal, clipboard text/image, screen QR, IME composition, and stale reveal rejection.");
                cx.update(|cx| cx.quit());
            })
            .detach();
        });
}

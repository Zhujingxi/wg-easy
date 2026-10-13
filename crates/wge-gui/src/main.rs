//! Unprivileged native desktop client. All tunnel ownership stays in the daemon.
#![forbid(unsafe_code)]
#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

mod appearance;
mod backend;
mod focus_scroll;
mod form;
mod import;
mod settings;
mod tray;
mod ui;

use backend::{Backend, Event, Intent};
use gpui_kit::*;
use settings::Settings;
use std::{sync::mpsc, time::Duration};
use wge_ipc::{Request, Response, Snapshot};

rust_i18n::i18n!("locales", fallback = "en");

struct Desktop {
    backend: Backend,
    snapshot: Snapshot,
    offline: bool,
    window: Option<AnyWindowHandle>,
    view: Option<Entity<ui::MainView>>,
    tray_ready: bool,
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    tray: Option<tray::NativeTray>,
}
impl Global for Desktop {}

fn open(cx: &mut App) {
    if let Some(window) = cx.global::<Desktop>().window
        && window
            .update(cx, |_, window, _| window.activate_window())
            .is_ok()
    {
        cx.activate(true);
        return;
    }
    let desktop = cx.global::<Desktop>();
    let backend = desktop.backend.clone();
    let snapshot = desktop.snapshot.clone();
    let offline = desktop.offline;
    let settings = Settings::load();
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::centered(size(px(1180.), px(800.)), cx)),
        window_min_size: Some(size(px(980.), px(680.))),
        titlebar: Some(TitlebarOptions {
            title: Some(rust_i18n::t!("app_name").into_owned().into()),
            ..Default::default()
        }),
        app_id: Some("io.github.zhujingxi.wireguardeasy".into()),
        ..Default::default()
    };
    match gpui_kit::open_window(options, cx, |window, cx| {
        let view = cx.new(|cx| ui::MainView::new(backend, snapshot, settings, offline, cx));
        window.on_window_should_close(cx, |window, cx| {
            if let Some(view) = cx.global::<Desktop>().view.clone() {
                view.update(cx, |view, cx| view.clear_secrets(window, cx));
            }
            cx.global_mut::<Desktop>().view = None;
            cx.global_mut::<Desktop>().window = None;
            if !cx.global::<Desktop>().tray_ready {
                cx.quit();
            }
            true
        });
        window.focus(&view.focus_handle(cx), cx);
        view
    }) {
        Ok((window, view)) => {
            let desktop = cx.global_mut::<Desktop>();
            desktop.window = Some(window);
            desktop.view = Some(view);
            cx.activate(true);
        }
        Err(_) => {
            eprintln!("{}", rust_i18n::t!("window_error"));
        }
    }
}
fn main() {
    let settings = Settings::load();
    if let Some(language) = settings.language.as_deref() {
        rust_i18n::set_locale(language);
    } else {
        let language = std::env::var("LC_ALL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("LANG").ok())
            .unwrap_or_default();
        let language = language.split(['_', '-', '.']).next().unwrap_or("en");
        if rust_i18n::available_locales!()
            .iter()
            .any(|l| l == language)
        {
            rust_i18n::set_locale(language);
        }
    }
    let background = std::env::args().any(|arg| arg == "--background");
    let (tx, rx) = mpsc::channel();
    let backend = backend::start(tx.clone());
    gpui_kit::application()
        .with_quit_mode(QuitMode::Explicit)
        .with_assets(appearance::Assets)
        .run(move |cx| {
            appearance::init(cx);
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            let tray = tray::NativeTray::new(tx);
            cx.set_global(Desktop {
                backend,
                snapshot: Snapshot::default(),
                offline: true,
                window: None,
                view: None,
                #[cfg(target_os = "linux")]
                tray_ready: false,
                #[cfg(any(target_os = "windows", target_os = "macos"))]
                tray_ready: tray.is_some(),
                #[cfg(any(target_os = "windows", target_os = "macos"))]
                tray,
            });
            if background
                && cfg!(any(target_os = "windows", target_os = "macos"))
                && !cx.global::<Desktop>().tray_ready
            {
                cx.quit();
                return;
            }
            if !background {
                open(cx);
            }
            cx.spawn(async move |cx| {
                loop {
                    cx.background_executor()
                        .timer(Duration::from_millis(200))
                        .await;
                    cx.update(|cx| {
                        #[cfg(any(target_os = "windows", target_os = "macos"))]
                        if let Some(tray) = &cx.global::<Desktop>().tray {
                            tray.poll();
                        }
                        for event in rx.try_iter() {
                            match event {
                                #[cfg(target_os = "linux")]
                                Event::TrayReady(ready) => {
                                    cx.global_mut::<Desktop>().tray_ready = ready;
                                    if !ready && background {
                                        cx.quit();
                                    }
                                }
                                Event::Open => open(cx),
                                Event::Quit => cx.quit(),
                                Event::Toggle(id, on) => {
                                    cx.global::<Desktop>().backend.send(
                                        if on {
                                            Request::Connect { id }
                                        } else {
                                            Request::Disconnect { id }
                                        },
                                        Intent::Action,
                                    );
                                }
                                event => {
                                    if matches!(event, Event::Offline) {
                                        cx.global_mut::<Desktop>().offline = true;
                                    }
                                    #[cfg(any(target_os = "windows", target_os = "macos"))]
                                    if matches!(event, Event::Offline)
                                        && let Some(tray) = &mut cx.global_mut::<Desktop>().tray
                                    {
                                        tray.update(&Snapshot::default());
                                    }
                                    if let Event::Reply(_, Response::Snapshot(snapshot)) = &event {
                                        let desktop = cx.global_mut::<Desktop>();
                                        desktop.snapshot = snapshot.clone();
                                        desktop.offline = false;
                                        #[cfg(any(target_os = "windows", target_os = "macos"))]
                                        if let Some(tray) = &mut desktop.tray {
                                            tray.update(snapshot);
                                        }
                                    }
                                    let desktop = cx.global::<Desktop>();
                                    if let (Some(window), Some(view)) =
                                        (desktop.window, desktop.view.clone())
                                    {
                                        let _ = window.update(cx, |_, window, cx| {
                                            view.update(cx, |view, cx| {
                                                view.event(event, window, cx)
                                            })
                                        });
                                    } else {
                                        match event {
                                            Event::Reply(
                                                Intent::Edit,
                                                Response::Tunnel(tunnel),
                                            ) if !tunnel.saved => {
                                                desktop.backend.send(
                                                    Request::DiscardDraft { id: tunnel.id },
                                                    Intent::Refresh,
                                                );
                                            }
                                            Event::Reply(
                                                Intent::SaveConnect,
                                                Response::Tunnel(tunnel),
                                            ) => {
                                                desktop.backend.send(
                                                    Request::Connect { id: tunnel.id },
                                                    Intent::Action,
                                                );
                                            }
                                            Event::Reply(
                                                Intent::DeleteAfterDisconnect,
                                                Response::Tunnel(tunnel),
                                            ) => {
                                                desktop.backend.send(
                                                    Request::Delete { id: tunnel.id },
                                                    Intent::Action,
                                                );
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
            })
            .detach();
        });
}

#[cfg(test)]
mod tests {
    #[test]
    fn bundled_translations_have_the_same_complete_keys() {
        let english: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(include_str!("../locales/en.json")).unwrap();
        let japanese: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(include_str!("../locales/ja.json")).unwrap();
        assert_eq!(
            english.keys().collect::<Vec<_>>(),
            japanese.keys().collect::<Vec<_>>()
        );
        assert!(
            english
                .values()
                .chain(japanese.values())
                .all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
        );
    }
}

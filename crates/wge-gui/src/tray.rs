use crate::backend::{Event, active};
use std::sync::mpsc::Sender;
use wge_ipc::{ConnectionState, Snapshot};

fn pixels(connected: bool) -> Vec<u8> {
    let color = if connected {
        [30, 126, 100]
    } else {
        [109, 119, 123]
    };
    let mut bytes = vec![0; 32 * 32 * 4];
    for y in 0_i32..32 {
        for x in 0_i32..32 {
            let edge = 9 + (y - 7).max(0) / 3;
            if (5..27).contains(&y) && (x - 16).abs() < (16 - edge).max(2) {
                let i = ((y * 32 + x) * 4) as usize;
                bytes[i..i + 4].copy_from_slice(&[color[0], color[1], color[2], 255]);
            }
        }
    }
    bytes
}

#[cfg(target_os = "linux")]
pub struct LinuxTray {
    pub snapshot: Snapshot,
    pub online: bool,
    events: Sender<Event>,
}
#[cfg(target_os = "linux")]
impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        "wireguardeasy".into()
    }
    fn title(&self) -> String {
        rust_i18n::t!("app_name").into_owned()
    }
    fn activate(&mut self, _: i32, _: i32) {
        let _ = self.events.send(Event::Open);
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let mut data = pixels(self.online && active(&self.snapshot));
        for pixel in data.chunks_exact_mut(4) {
            pixel.rotate_right(1);
        }
        vec![ksni::Icon {
            width: 32,
            height: 32,
            data,
        }]
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::{CheckmarkItem, StandardItem};
        let mut entries = vec![
            StandardItem {
                label: rust_i18n::t!("open_app").into_owned(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.events.send(Event::Open);
                }),
                ..Default::default()
            }
            .into(),
        ];
        for tunnel in self.snapshot.tunnels.iter().filter(|t| t.saved) {
            let id = tunnel.id.clone();
            let checked = !matches!(
                tunnel.status.state,
                ConnectionState::Off | ConnectionState::Error
            );
            entries.push(
                CheckmarkItem {
                    label: tunnel.name.replace('_', "__"),
                    checked,
                    enabled: self.online,
                    activate: Box::new(move |this: &mut Self| {
                        let _ = this.events.send(Event::Toggle(id.clone(), !checked));
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }
        entries.push(ksni::MenuItem::Separator);
        entries.push(
            StandardItem {
                label: rust_i18n::t!("quit_app").into_owned(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.events.send(Event::Quit);
                }),
                ..Default::default()
            }
            .into(),
        );
        entries
    }
}
#[cfg(target_os = "linux")]
pub async fn start(events: Sender<Event>) -> Option<ksni::Handle<LinuxTray>> {
    use ksni::TrayMethods;
    LinuxTray {
        snapshot: Snapshot::default(),
        online: false,
        events,
    }
    .spawn()
    .await
    .ok()
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
pub struct NativeTray {
    tray: tray_icon::TrayIcon,
    events: Sender<Event>,
    entries: Vec<(tray_icon::menu::MenuId, wge_ipc::TunnelId, bool)>,
}
#[cfg(any(target_os = "windows", target_os = "macos"))]
impl NativeTray {
    pub fn new(events: Sender<Event>) -> Option<Self> {
        let icon = tray_icon::Icon::from_rgba(pixels(false), 32, 32).ok()?;
        let tray = tray_icon::TrayIconBuilder::new()
            .with_icon(icon)
            .with_tooltip(rust_i18n::t!("app_name").as_ref())
            .build()
            .ok()?;
        let mut this = Self {
            tray,
            events,
            entries: Vec::new(),
        };
        this.update(&Snapshot::default());
        Some(this)
    }
    pub fn update(&mut self, snapshot: &Snapshot) {
        use tray_icon::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
        let menu = Menu::new();
        let open = MenuItem::with_id("open", rust_i18n::t!("open_app"), true, None);
        let _ = menu.append(&open);
        self.entries.clear();
        for tunnel in snapshot.tunnels.iter().filter(|t| t.saved) {
            let enabled = !matches!(
                tunnel.status.state,
                ConnectionState::Off | ConnectionState::Error
            );
            let item = CheckMenuItem::new(&tunnel.name, true, enabled, None);
            self.entries
                .push((item.id().clone(), tunnel.id.clone(), !enabled));
            let _ = menu.append(&item);
        }
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&MenuItem::with_id(
            "quit",
            rust_i18n::t!("quit_app"),
            true,
            None,
        ));
        self.tray.set_menu(Some(Box::new(menu)));
        if let Ok(icon) = tray_icon::Icon::from_rgba(pixels(active(snapshot)), 32, 32) {
            let _ = self.tray.set_icon(Some(icon));
        }
    }
    pub fn poll(&self) {
        while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            if event.id.as_ref() == "open" {
                let _ = self.events.send(Event::Open);
            } else if event.id.as_ref() == "quit" {
                let _ = self.events.send(Event::Quit);
            } else if let Some((_, id, on)) = self.entries.iter().find(|(id, _, _)| *id == event.id)
            {
                let _ = self.events.send(Event::Toggle(id.clone(), *on));
            }
        }
        while let Ok(event) = tray_icon::TrayIconEvent::receiver().try_recv() {
            if matches!(event, tray_icon::TrayIconEvent::DoubleClick { .. }) {
                let _ = self.events.send(Event::Open);
            }
        }
    }
}

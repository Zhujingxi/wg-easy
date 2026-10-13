use gpui_kit::component as gpui_component;
use gpui_kit::component::{Theme, ThemeMode};
use gpui_kit::{App, AssetSource, Result, SharedString, px, rgb};
use std::borrow::Cow;

gpui_kit::assets::icon_assets!(
    ExtraIcons,
    [
        Waypoints,
        ClipboardPaste,
        ScanLine,
        Import,
        LockKeyhole,
        Laptop,
        Server
    ]
);
pub struct Assets;
impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some(icon) = ExtraIcons.load(path)? {
            Ok(Some(icon))
        } else {
            gpui_kit::assets::Assets.load(path)
        }
    }
    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut paths = gpui_kit::assets::Assets.list(path)?;
        paths.extend(ExtraIcons.list(path)?);
        Ok(paths)
    }
}
pub fn init(cx: &mut App) {
    rust_i18n::extend!(gpui_component);
    gpui_kit::init(cx);
    Theme::change(ThemeMode::Light, None, cx);
    Theme::update(cx, |theme| {
        theme.font_size = px(14.);
        theme.radius = px(8.);
        theme.radius_lg = px(12.);
        theme.primary = rgb(0x24785f).into();
        theme.primary_foreground = rgb(0xffffff).into();
        theme.button_primary = theme.primary;
        theme.button_primary_foreground = theme.primary_foreground;
        theme.button_primary_hover = rgb(0x1c674f).into();
        theme.button_primary_active = rgb(0x14523f).into();
        theme.ring = rgb(0x24785f).into();
    });
}

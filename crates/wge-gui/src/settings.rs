use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{fs, io, path::PathBuf};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub language: Option<String>,
    pub start_at_login: bool,
}

fn settings_path() -> io::Result<PathBuf> {
    ProjectDirs::from("org", "wireguardeasy", "wireguardeasy")
        .map(|dirs| dirs.config_dir().join("settings.json"))
        .ok_or_else(|| io::Error::other("User config directory unavailable"))
}

impl Settings {
    pub fn load() -> Self {
        settings_path()
            .ok()
            .and_then(|p| fs::read(p).ok())
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> io::Result<()> {
        let path = settings_path()?;
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| io::Error::other("Invalid config directory"))?,
        )?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, serde_json::to_vec(self)?)?;
        fs::rename(temporary, path)
    }

    pub fn set_login(&mut self, enabled: bool) -> io::Result<()> {
        register_login(enabled)?;
        self.start_at_login = enabled;
        self.save()
    }
}

#[cfg(target_os = "linux")]
fn register_login(enabled: bool) -> io::Result<()> {
    let dirs = directories::BaseDirs::new()
        .ok_or_else(|| io::Error::other("User directory unavailable"))?;
    let path = dirs.config_dir().join("autostart/wireguardeasy.desktop");
    if !enabled {
        return remove_if_exists(path);
    }
    let exe = std::env::current_exe()?;
    let command = desktop_quote(&exe.to_string_lossy());
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(
        path,
        format!(
            "[Desktop Entry]\nType=Application\nName=wg-easy\nExec={command} --background\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
        ),
    )
}

#[cfg(target_os = "linux")]
fn desktop_quote(value: &str) -> String {
    let mut result = String::from("\"");
    for ch in value.chars() {
        match ch {
            '%' => result.push_str("%%"),
            '\\' => result.push_str("\\\\\\\\"),
            '"' | '`' | '$' => {
                result.push_str("\\\\");
                result.push(ch);
            }
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            ch => result.push(ch),
        }
    }
    result.push('"');
    result
}

#[cfg(target_os = "macos")]
fn register_login(enabled: bool) -> io::Result<()> {
    let dirs = directories::BaseDirs::new()
        .ok_or_else(|| io::Error::other("User directory unavailable"))?;
    let path = dirs
        .home_dir()
        .join("Library/LaunchAgents/org.wireguardeasy.gui.plist");
    if !enabled {
        return remove_if_exists(path);
    }
    let exe = std::env::current_exe()?
        .to_string_lossy()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(
        path,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>org.wireguardeasy.gui</string><key>ProgramArguments</key><array><string>{exe}</string><string>--background</string></array><key>RunAtLoad</key><true/></dict></plist>"
        ),
    )
}

#[cfg(windows)]
fn register_login(enabled: bool) -> io::Result<()> {
    use winreg::{
        RegKey,
        enums::{HKEY_CURRENT_USER, KEY_SET_VALUE},
    };
    let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        KEY_SET_VALUE,
    )?;
    if enabled {
        let exe = std::env::current_exe()?;
        key.set_value(
            "WireGuardEasy",
            &format!("\"{}\" --background", exe.display()),
        )
    } else {
        match key.delete_value("WireGuardEasy") {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

#[cfg(unix)]
fn remove_if_exists(path: PathBuf) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn login_defaults_off_and_language_can_be_extended() {
        let value: Settings = serde_json::from_str("{}").unwrap();
        assert!(!value.start_at_login);
        let value: Settings = serde_json::from_str(r#"{"language":"fr"}"#).unwrap();
        assert_eq!(value.language.as_deref(), Some("fr"));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn executable_is_literal_in_desktop_entry() {
        assert_eq!(
            desktop_quote("/home/a b/100%/wg-easy"),
            "\"/home/a b/100%%/wg-easy\""
        );
        assert!(!desktop_quote("bad\nExec=bad").contains('\n'));
    }
}

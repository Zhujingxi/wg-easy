use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
};
use wge_ipc::SensitiveText;
use zeroize::Zeroizing;

const MAX_IMAGE_BYTES: u64 = 24 * 1024 * 1024;

pub fn open(path: &Path) -> Result<SensitiveText, &'static str> {
    let file = File::open(path).map_err(|_| "import_read_error")?;
    if file.metadata().map_err(|_| "import_read_error")?.len() > MAX_IMAGE_BYTES {
        return Err("import_too_large");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "import_read_error")?;
    if bytes.len() > MAX_IMAGE_BYTES as usize {
        return Err("import_too_large");
    }
    if let Ok(text) = std::str::from_utf8(&bytes)
        && text
            .trim_start_matches('\u{feff}')
            .trim_start()
            .contains("[Interface]")
    {
        if bytes.len() > wge_config::MAX_CONFIG_BYTES {
            return Err("import_too_large");
        }
        return Ok(SensitiveText::new(text.to_owned()));
    }
    decode_image(&bytes)
}

pub fn decode_image(bytes: &[u8]) -> Result<SensitiveText, &'static str> {
    if bytes.len() > MAX_IMAGE_BYTES as usize {
        return Err("import_too_large");
    }
    let mut reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| "import_image_error")?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode().map_err(|_| "import_image_error")?;
    decode_gray(image.to_luma8())
}

fn decode_gray(image: image::GrayImage) -> Result<SensitiveText, &'static str> {
    let mut prepared = rqrr::PreparedImage::prepare(image);
    for grid in prepared.detect_grids() {
        if let Ok((_, content)) = grid.decode() {
            let content = Zeroizing::new(content);
            if content
                .trim_start_matches('\u{feff}')
                .trim_start()
                .contains("[Interface]")
            {
                if content.len() > wge_config::MAX_CONFIG_BYTES {
                    return Err("import_too_large");
                }
                return Ok(SensitiveText::new(content.to_string()));
            }
        }
    }
    Err("qr_not_found")
}

pub fn screen() -> Result<SensitiveText, &'static str> {
    let monitors = xcap::Monitor::all().map_err(|_| "screen_permission")?;
    for monitor in monitors {
        let rgba = monitor.capture_image().map_err(|_| "screen_permission")?;
        if let Ok(text) = decode_gray(image::DynamicImage::ImageRgba8(rgba).to_luma8()) {
            return Ok(text);
        }
    }
    Err("qr_not_found")
}

pub fn qr_png(text: &str) -> Option<Vec<u8>> {
    let qr = qrcode::QrCode::new(text).ok()?;
    let image = qr
        .render::<image::Luma<u8>>()
        .min_dimensions(192, 192)
        .build();
    let mut bytes = Cursor::new(Vec::new());
    image::DynamicImage::ImageLuma8(image)
        .write_to(&mut bytes, image::ImageFormat::Png)
        .ok()?;
    Some(bytes.into_inner())
}

pub fn write_export(path: &Path, content: &SensitiveText) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    use std::io::Write;
    file.write_all(content.expose().as_bytes())?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_qr_roundtrip_and_non_config_rejection() {
        let config = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/24\n";
        assert_eq!(
            decode_image(&qr_png(config).unwrap()).unwrap().expose(),
            config
        );
        assert!(decode_image(&qr_png("https://example.com").unwrap()).is_err());
        assert!(decode_image(b"not an image").is_err());
    }
    #[test]
    fn tiff_clipboard_qr_is_accepted() {
        let config = "[Interface]\nAddress = 10.0.0.2/32\n";
        let image = image::load_from_memory(&qr_png(config).unwrap()).unwrap();
        let mut tiff = Cursor::new(Vec::new());
        image.write_to(&mut tiff, image::ImageFormat::Tiff).unwrap();
        assert_eq!(decode_image(tiff.get_ref()).unwrap().expose(), config);
    }
    #[test]
    fn standard_configs_can_start_with_comments() {
        let path = std::env::temp_dir().join(format!("wge-import-{}.conf", std::process::id()));
        let config = "# Provided by the administrator\n[Interface]\nAddress = 10.0.0.2/32\n";
        std::fs::write(&path, config).unwrap();
        assert_eq!(open(&path).unwrap().expose(), config);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn export_never_overwrites_an_existing_file() {
        let path = std::env::temp_dir().join(format!("wge-export-{}.conf", std::process::id()));
        std::fs::write(&path, "existing").unwrap();
        assert!(write_export(&path, &SensitiveText::new("new secret".into())).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "existing");
        std::fs::remove_file(path).unwrap();
    }
}

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use wge_config::TunnelConfig;
use wge_ipc::TunnelId;
use zeroize::Zeroizing;

const MAX_STORED_BYTES: u64 = 1024 * 1024;
const NAME_PREFIX: &str = "# wg-easy-name: ";

pub struct StoredTunnel {
    pub owner: String,
    pub id: TunnelId,
    pub name: String,
    pub config: TunnelConfig,
}
pub struct Store {
    root: PathBuf,
}
impl Store {
    pub fn open(root: PathBuf) -> std::io::Result<Self> {
        private_directory(&root)?;
        Ok(Self { root })
    }
    fn owner_directory(&self, owner: &str) -> std::io::Result<PathBuf> {
        if owner.is_empty()
            || owner.len() > 184
            || !owner
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
        {
            return Err(invalid("Invalid account identity"));
        }
        let directory = self.root.join(owner);
        private_directory(&directory)?;
        Ok(directory)
    }
    fn path(&self, owner: &str, id: &TunnelId) -> std::io::Result<PathBuf> {
        if !id.is_valid() {
            return Err(invalid("Invalid tunnel ID"));
        }
        Ok(self.owner_directory(owner)?.join(format!("{}.conf", id.0)))
    }
    pub fn save(&self, tunnel: &StoredTunnel) -> std::io::Result<()> {
        let path = self.path(&tunnel.owner, &tunnel.id)?;
        let bytes = wge_config::write(&tunnel.config)
            .map_err(|_| invalid("Invalid tunnel configuration"))?;
        let mut content = Zeroizing::new(format!(
            "{NAME_PREFIX}{}\n",
            serde_json::to_string(&tunnel.name).map_err(|_| invalid("Invalid name"))?
        ));
        content.push_str(&bytes);
        let temporary = path.with_extension("pending");
        // An interrupted write may leave a private temporary file, never a partial config.
        if temporary.try_exists()? {
            fs::remove_file(&temporary)?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        let mut file = options.open(&temporary)?;
        let result = (|| {
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &path)?;
            sync_parent(&path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    pub fn remove(&self, owner: &str, id: &TunnelId) -> std::io::Result<()> {
        let path = self.path(owner, id)?;
        fs::remove_file(&path)?;
        sync_parent(&path)
    }
    pub fn load_all(&self) -> std::io::Result<Vec<StoredTunnel>> {
        let mut tunnels = Vec::new();
        for account in fs::read_dir(&self.root)? {
            let account = account?;
            if !account.file_type()?.is_dir() {
                continue;
            }
            let owner = account.file_name().to_string_lossy().into_owned();
            let directory = self.owner_directory(&owner)?;
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|x| x.to_str()) != Some("conf") {
                    continue;
                }
                if !entry.file_type()?.is_file() {
                    return Err(invalid("Tunnel storage contains an unsafe entry"));
                }
                let id = TunnelId(
                    path.file_stem()
                        .and_then(|x| x.to_str())
                        .unwrap_or_default()
                        .to_owned(),
                );
                if !id.is_valid() {
                    return Err(invalid("Tunnel storage contains an invalid ID"));
                }
                let mut options = OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
                }
                let file = options.open(&path)?;
                if file.metadata()?.len() > MAX_STORED_BYTES {
                    return Err(invalid("Stored tunnel exceeds the size limit"));
                }
                let mut text = Zeroizing::new(String::new());
                file.take(MAX_STORED_BYTES + 1).read_to_string(&mut text)?;
                if text.len() as u64 > MAX_STORED_BYTES {
                    return Err(invalid("Stored tunnel exceeds the size limit"));
                }
                let name = text
                    .lines()
                    .next()
                    .and_then(|line| line.strip_prefix(NAME_PREFIX))
                    .and_then(|name| serde_json::from_str::<String>(name).ok())
                    .ok_or_else(|| invalid("Stored tunnel name is invalid"))?;
                let config = wge_config::parse(&text)
                    .map_err(|_| invalid("Stored tunnel configuration is invalid"))?;
                tunnels.push(StoredTunnel {
                    owner: owner.clone(),
                    id,
                    name,
                    config,
                });
            }
        }
        Ok(tunnels)
    }
}
fn invalid(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}
pub fn private_directory(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid("The service directory is unsafe"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != rustix::process::geteuid().as_raw()
                    || metadata.mode() & 0o077 != 0
                {
                    return Err(invalid(
                        "The service directory must be owned by this account with mode 0700",
                    ));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(path)?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(path.parent().ok_or_else(|| invalid("No storage parent"))?)?.sync_all()?;
    Ok(())
}

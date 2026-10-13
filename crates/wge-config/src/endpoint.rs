use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use crate::{ConfigError, ErrorKind, validate_domain};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::new(ErrorKind::InvalidPort, "Endpoint"));
        }
        let valid = match self.host.parse::<IpAddr>() {
            Ok(address) => {
                !address.is_unspecified()
                    && !address.is_multicast()
                    && !matches!(address, IpAddr::V4(address) if address.is_broadcast())
            }
            Err(_) => validate_domain(&self.host),
        };
        if !valid {
            return Err(ConfigError::new(ErrorKind::InvalidEndpoint, "Endpoint"));
        }
        Ok(())
    }
}

impl FromStr for Endpoint {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || ConfigError::new(ErrorKind::InvalidEndpoint, "Endpoint");
        let (host, port) = if let Some(rest) = value.strip_prefix('[') {
            let (host, port) = rest.split_once("]:").ok_or_else(invalid)?;
            host.parse::<Ipv6Addr>().map_err(|_| invalid())?;
            (host, port)
        } else {
            let (host, port) = value.rsplit_once(':').ok_or_else(invalid)?;
            if host.contains(':') {
                return Err(invalid());
            }
            (host, port)
        };
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ConfigError::new(ErrorKind::InvalidPort, "Endpoint"));
        }
        let endpoint = Self {
            host: host.to_owned(),
            port: port
                .parse()
                .map_err(|_| ConfigError::new(ErrorKind::InvalidPort, "Endpoint"))?,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

use std::fmt;

/// Stable categories let the UI translate errors without matching English text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ErrorKind {
    #[error("The configuration is too large.")]
    TooLarge,
    #[error("Use a section heading or a setting followed by = and its value.")]
    Syntax,
    #[error("This section is not supported.")]
    UnsupportedSection,
    #[error("This setting is not supported.")]
    UnsupportedField,
    #[error("Command hooks are not supported. Remove the hook before importing.")]
    ScriptHook,
    #[error("This setting appears more than once.")]
    DuplicateField,
    #[error("This required setting is missing.")]
    MissingField,
    #[error("Enter a nonzero WireGuard key encoded as 44 Base64 characters.")]
    InvalidKey,
    #[error("Enter an IPv4 or IPv6 address with a valid prefix length.")]
    InvalidAddress,
    #[error("Enter a unicast IPv4 or IPv6 DNS address, or a valid search domain.")]
    InvalidDns,
    #[error("Enter a server name or IP address and a port; put IPv6 addresses in brackets.")]
    InvalidEndpoint,
    #[error("The server port must be between 1 and 65535.")]
    InvalidPort,
    #[error("MTU must be between 576 and 65535, and at least 1280 when IPv6 is used.")]
    InvalidMtu,
    #[error("Keepalive must be between 0 and 65535 seconds; 0 disables it.")]
    InvalidKeepalive,
    #[error("Add at least one server.")]
    MissingPeer,
    #[error("Add at least one tunnel address.")]
    MissingAddress,
    #[error("Add at least one traffic range for each server.")]
    MissingRoutes,
    #[error("This configuration has too many addresses, servers or traffic ranges.")]
    TooManyItems,
    #[error("Each server must have a different public key.")]
    DuplicatePeer,
    #[error("A server cannot use this device's own public key.")]
    OwnPublicKey,
    #[error("Enter a name of 1 to 80 characters without control characters.")]
    InvalidName,
}

/// Errors never retain setting values, which can contain private keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    pub kind: ErrorKind,
    pub field: &'static str,
    pub line: Option<usize>,
}

impl ConfigError {
    pub(crate) fn new(kind: ErrorKind, field: &'static str) -> Self {
        Self {
            kind,
            field,
            line: None,
        }
    }

    pub(crate) fn at(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.line {
            write!(f, "Line {line}: ")?;
        }
        write!(f, "{}: {}", self.field, self.kind)
    }
}

impl std::error::Error for ConfigError {}

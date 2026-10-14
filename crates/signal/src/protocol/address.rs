//! `ProtocolAddress` — espelho de `libsignal/src/protocol_address.js`.

use crate::error::SignalError;
use crate::Result;

/// Address `<id>.<deviceId>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolAddress {
    pub id: String,
    pub device_id: u32,
}

impl ProtocolAddress {
    pub fn new(id: impl Into<String>, device_id: u32) -> Self {
        Self {
            id: id.into(),
            device_id,
        }
    }

    /// Parse from `<id>.<deviceId>`.
    pub fn from(encoded: &str) -> Result<Self> {
        if !encoded.contains('.') {
            return Err(SignalError::InvalidAddress);
        }
        let (id, device) = encoded
            .rsplit_once('.')
            .ok_or(SignalError::InvalidAddress)?;
        let device_id: u32 = device
            .parse()
            .map_err(|_| SignalError::InvalidAddress)?;
        Ok(Self::new(id, device_id))
    }

    pub fn to_string(&self) -> String {
        format!("{}.{}", self.id, self.device_id)
    }

    pub fn is(&self, other: &ProtocolAddress) -> bool {
        self.id == other.id && self.device_id == other.device_id
    }
}

impl std::fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.id, self.device_id)
    }
}

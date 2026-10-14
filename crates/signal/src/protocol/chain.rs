//! Chain types — espelho de `base_key_type.js` / `chain_type.js`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BaseKeyType {
    Ours = 1,
    Theirs = 2,
}

impl BaseKeyType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(BaseKeyType::Ours),
            2 => Some(BaseKeyType::Theirs),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChainType {
    Sending = 1,
    Receiving = 2,
}

impl ChainType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(ChainType::Sending),
            2 => Some(ChainType::Receiving),
            _ => None,
        }
    }
}

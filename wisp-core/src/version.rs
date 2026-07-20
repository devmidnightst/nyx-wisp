#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WispVersion {
    pub major: u8,
    pub minor: u8,
}

impl WispVersion {
    pub const V2: WispVersion = WispVersion { major: 2, minor: 1 };

    pub fn is_major_compatible(self, other: WispVersion) -> bool {
        self.major == other.major
    }
}

//! PIV slot helpers on top of the yubikey crate.

use yubikey::Version;
use yubikey::piv::SlotId;

/// All PIV slots reported by `info` and `backup`: the four standard slots
/// and the retired ones 82 to 95.
pub fn all_piv_slots() -> Vec<(SlotId, String)> {
    use yubikey::piv::RetiredSlotId;

    let mut slots = vec![
        (SlotId::Authentication, "9a".to_string()),
        (SlotId::Signature, "9c".to_string()),
        (SlotId::KeyManagement, "9d".to_string()),
        (SlotId::CardAuthentication, "9e".to_string()),
    ];
    for raw in 0x82..=0x95u8 {
        if let Ok(retired) = RetiredSlotId::try_from(raw) {
            slots.push((SlotId::Retired(retired), format!("{raw:02x}")));
        }
    }
    slots
}

/// Slot metadata arrived with firmware 5.2.3; only report it from 5.3 on.
pub fn metadata_supported(version: Version) -> bool {
    (version.major, version.minor) >= (5, 3)
}

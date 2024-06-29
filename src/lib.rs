#![no_std]
extern crate alloc;

use base64::engine::GeneralPurpose;

pub mod keystore;
pub mod privkey;
pub mod pubkey;

// entire lib will use the standard base64 engine
pub(crate) const B64_ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;

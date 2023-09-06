#![no_std]
extern crate alloc;

mod privkey;
mod pubkey;
mod tests;

// type Result<T> = std::result::Result<T, Box<dyn error::Error>>;
type Bytes = [u8];


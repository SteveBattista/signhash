//! SignHash Library
//! 
//! Provides cryptographic file hashing and signing functionality.

pub mod hash_helper;
pub mod main_helper;

// Re-export commonly used types for convenience  
pub use hash_helper::{HasherOptions, Algorithm, hash_file};

// Re-export main_helper types and functions
pub use main_helper::*;
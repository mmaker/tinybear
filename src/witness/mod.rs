pub mod trace;

/// AES key schedule witness generation.
pub mod keyschedule;

// AES cipher witness generation.
pub mod cipher;

/// Registry: store and retrieve chunks of the witness.
pub mod registry;

/// AES GCM witness generation
pub mod gcm;

// Re-export common functions
pub use trace::cipher::AesCipherTrace;
pub use trace::cipher::{aes128, aes256};
pub use trace::keyschedule::{aes128_keyschedule, aes256_keyschedule};

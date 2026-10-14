//! The BLS (Boneh-Lynn-Shacham) cryptographic backend implementation is determined
//! at compile time via feature flags. Two implementations are supported:
//! - "supranational": Uses the supranational/blst library, optimized for performance
//! - "zkcrypto": Uses the zkcrypto/bls12_381 library implementation, optimized for zkVMs

pub mod constants;
pub mod errors;
pub mod private_key;
pub mod public_key;
pub mod signature;
pub mod traits;

pub use private_key::PrivateKey;
pub use public_key::PublicKey;
pub use signature::BLSSignature;

#[cfg(feature = "supranational")]
pub mod supranational;
#[cfg(feature = "zkcrypto")]
pub mod zkcrypto;

#[cfg(feature = "zkcrypto")]
pub use zkcrypto::public_key::prewarm_public_keys;

/// No-op: only the zkcrypto backend caches keys.
#[cfg(not(feature = "zkcrypto"))]
pub fn prewarm_public_keys(_public_keys: &[PublicKey]) -> usize {
    0
}

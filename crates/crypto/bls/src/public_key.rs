use std::str::FromStr;

use alloy_primitives::{FixedBytes, hex};
use anyhow::anyhow;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::errors::BLSError;

/// A compressed BLS public key. The bytes are stored inline: a mainnet state holds millions of
/// keys, and a heap allocation per key made copying or freeing a state cost tens of milliseconds.
#[derive(Debug, PartialEq, Clone, Encode, Decode, TreeHash, Default, Eq, Hash)]
pub struct PublicKey {
    pub inner: FixedBytes<48>,
}

impl PublicKey {
    pub fn to_bytes(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let val = format!("0x{}", hex::encode(self.inner));
        serializer.serialize_str(&val)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let result: String = Deserialize::deserialize(deserializer)?;
        let result = hex::decode(&result).map_err(serde::de::Error::custom)?;
        let key = FixedBytes::try_from(result.as_slice()).map_err(serde::de::Error::custom)?;
        Ok(Self { inner: key })
    }
}

impl FromStr for PublicKey {
    type Err = BLSError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean_str = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(clean_str).map_err(BLSError::InvalidHexString)?;

        if bytes.len() != 48 {
            return Err(BLSError::InvalidByteLength(anyhow!(
                "Expected 48 bytes for PublicKey, got {} bytes",
                bytes.len()
            )));
        }

        Ok(PublicKey {
            inner: FixedBytes::from_slice(&bytes),
        })
    }
}

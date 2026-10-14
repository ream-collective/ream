#[cfg(not(target_os = "zkvm"))]
use std::{
    collections::HashMap,
    sync::{LazyLock, RwLock},
};

use anyhow::anyhow;
use bls12_381::{G1Affine, G1Projective};

use crate::{
    PublicKey,
    errors::BLSError,
    traits::{Aggregatable, ZkcryptoAggregatable},
};

impl From<G1Projective> for PublicKey {
    fn from(value: G1Projective) -> Self {
        Self {
            inner: G1Affine::from(value).to_compressed().into(),
        }
    }
}

impl TryFrom<&PublicKey> for G1Affine {
    type Error = BLSError;

    fn try_from(value: &PublicKey) -> Result<Self, Self::Error> {
        match G1Affine::from_compressed(&value.to_bytes().try_into().map_err(|err| {
            BLSError::InvalidByteLength(anyhow!("Failed to convert to array {err:?}"))
        })?)
        .into_option()
        {
            Some(point) => Ok(point),
            None => Err(BLSError::InvalidPublicKey(anyhow!(
                "Invalid public key point"
            ))),
        }
    }
}

/// Validator keys that were already decompressed. Decompressing a key checks that it is on the
/// curve and in the G1 subgroup, which costs more than the pairing that uses it, and every
/// attestation aggregates the same validator keys again. Only individual keys are cached, never
/// aggregates, so the size follows the validator registry.
#[cfg(not(target_os = "zkvm"))]
static DECOMPRESSED_PUBLIC_KEYS: LazyLock<RwLock<HashMap<[u8; 48], G1Affine>>> =
    LazyLock::new(Default::default);

/// Above mainnet's validator count. Reaching it means keys that are not validators are being
/// verified, so the cache starts over rather than growing without bound.
#[cfg(not(target_os = "zkvm"))]
const MAX_CACHED_PUBLIC_KEYS: usize = 4_000_000;

fn key_bytes(public_key: &PublicKey) -> Result<[u8; 48], BLSError> {
    public_key
        .to_bytes()
        .try_into()
        .map_err(|err| BLSError::InvalidByteLength(anyhow!("Failed to convert to array {err:?}")))
}

/// Decompresses a single public key, reusing an earlier decompression of the same bytes.
#[cfg(not(target_os = "zkvm"))]
pub(crate) fn decompress_public_key(public_key: &PublicKey) -> Result<G1Affine, BLSError> {
    let bytes = key_bytes(public_key)?;
    if let Some(point) = DECOMPRESSED_PUBLIC_KEYS
        .read()
        .expect("public key cache lock is not poisoned")
        .get(&bytes)
    {
        return Ok(*point);
    }
    let point = G1Affine::try_from(public_key)?;
    let mut cache = DECOMPRESSED_PUBLIC_KEYS
        .write()
        .expect("public key cache lock is not poisoned");
    if cache.len() >= MAX_CACHED_PUBLIC_KEYS {
        cache.clear();
    }
    cache.insert(bytes, point);
    Ok(point)
}

#[cfg(target_os = "zkvm")]
pub(crate) fn decompress_public_key(public_key: &PublicKey) -> Result<G1Affine, BLSError> {
    G1Affine::try_from(public_key)
}

/// Decompresses `public_keys` into the cache ahead of use, spread over the available cores, and
/// returns how many were added. A node calls this for its validators at startup, so that the
/// first epoch of attestations does not pay for decompressing every key one at a time. Invalid
/// keys are skipped; verifying with them later reports the error.
#[cfg(not(target_os = "zkvm"))]
pub fn prewarm_public_keys(public_keys: &[PublicKey]) -> usize {
    let missing: Vec<&PublicKey> = {
        let cache = DECOMPRESSED_PUBLIC_KEYS
            .read()
            .expect("public key cache lock is not poisoned");
        public_keys
            .iter()
            .filter(|public_key| {
                key_bytes(public_key).is_ok_and(|bytes| !cache.contains_key(&bytes))
            })
            .collect()
    };
    let threads = std::thread::available_parallelism().map_or(1, |threads| threads.get());
    let chunk_size = missing.len().div_ceil(threads).max(1);
    let decompressed: Vec<([u8; 48], G1Affine)> = std::thread::scope(|scope| {
        let workers: Vec<_> = missing
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .filter_map(|public_key| {
                            Some((
                                key_bytes(public_key).ok()?,
                                G1Affine::try_from(*public_key).ok()?,
                            ))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("decompression worker does not panic"))
            .collect()
    });

    let mut cache = DECOMPRESSED_PUBLIC_KEYS
        .write()
        .expect("public key cache lock is not poisoned");
    if cache.len() + decompressed.len() > MAX_CACHED_PUBLIC_KEYS {
        return 0;
    }
    let added = decompressed.len();
    cache.extend(decompressed);
    added
}

#[cfg(target_os = "zkvm")]
pub fn prewarm_public_keys(_public_keys: &[PublicKey]) -> usize {
    0
}

/// Below this many keys an aggregate is summed on the calling thread: starting threads costs more
/// than the additions they would share.
#[cfg(not(target_os = "zkvm"))]
const PARALLEL_AGGREGATION_THRESHOLD: usize = 4096;

/// Sum of the given individual public keys as a curve point. A mainnet attestation aggregates
/// about 30,000 keys, so large sets are summed in parallel chunks.
pub(crate) fn aggregate_public_key_point(
    public_keys: &[&PublicKey],
) -> Result<G1Projective, BLSError> {
    #[cfg(not(target_os = "zkvm"))]
    if public_keys.len() >= PARALLEL_AGGREGATION_THRESHOLD {
        let threads = std::thread::available_parallelism().map_or(1, |threads| threads.get());
        let chunk_size = public_keys.len().div_ceil(threads);
        let partial_sums: Vec<Result<G1Projective, BLSError>> = std::thread::scope(|scope| {
            let workers: Vec<_> = public_keys
                .chunks(chunk_size)
                .map(|chunk| scope.spawn(move || sum_public_keys(chunk)))
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("aggregation worker does not panic"))
                .collect()
        });
        return partial_sums
            .into_iter()
            .try_fold(G1Projective::identity(), |sum, partial| Ok(sum + partial?));
    }
    sum_public_keys(public_keys)
}

fn sum_public_keys(public_keys: &[&PublicKey]) -> Result<G1Projective, BLSError> {
    let mut accumulator = G1Projective::identity();
    #[cfg(not(target_os = "zkvm"))]
    let mut missing = Vec::new();
    #[cfg(target_os = "zkvm")]
    let missing = public_keys;
    #[cfg(not(target_os = "zkvm"))]
    {
        // One read lock for the whole sum; keys seen for the first time are added below.
        let cache = DECOMPRESSED_PUBLIC_KEYS
            .read()
            .expect("public key cache lock is not poisoned");
        for public_key in public_keys {
            match cache.get(&key_bytes(public_key)?) {
                Some(point) => accumulator = accumulator.add_mixed(point),
                None => missing.push(*public_key),
            }
        }
    }
    for public_key in missing.iter() {
        accumulator = accumulator.add_mixed(&decompress_public_key(public_key)?);
    }
    Ok(accumulator)
}

impl Aggregatable<PublicKey> for PublicKey {
    type Error = BLSError;

    fn aggregate(public_keys: &[&PublicKey]) -> Result<PublicKey, Self::Error> {
        Ok(PublicKey::from(aggregate_public_key_point(public_keys)?))
    }
}

impl ZkcryptoAggregatable<PublicKey> for PublicKey {}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, FixedBytes};

    use super::*;
    use crate::{
        BLSSignature, PrivateKey,
        traits::{Signable, Verifiable},
    };

    fn private_key(index: u8) -> PrivateKey {
        PrivateKey {
            inner: B256::with_last_byte(index + 1),
        }
    }

    #[test]
    fn cached_keys_aggregate_and_verify_like_fresh_decompression() {
        let message = b"attestation data root";
        let private_keys: Vec<PrivateKey> = (0..5).map(private_key).collect();
        let public_keys: Vec<PublicKey> = private_keys
            .iter()
            .map(|key| key.public_key().unwrap())
            .collect();
        let key_refs: Vec<&PublicKey> = public_keys.iter().collect();
        let signatures: Vec<BLSSignature> = private_keys
            .iter()
            .map(|key| key.sign(message).unwrap())
            .collect();
        let signature = BLSSignature::aggregate(&signatures.iter().collect::<Vec<_>>()).unwrap();

        let uncached =
            PublicKey::from(key_refs.iter().fold(G1Projective::identity(), |sum, key| {
                sum + G1Projective::from(G1Affine::try_from(*key).unwrap())
            }));
        // The second round reads every key from the cache.
        for _ in 0..2 {
            assert_eq!(PublicKey::aggregate(&key_refs).unwrap(), uncached);
            assert!(signature.fast_aggregate_verify(&key_refs, message).unwrap());
            assert!(
                !signature
                    .fast_aggregate_verify(&key_refs, b"other message")
                    .unwrap()
            );
            assert!(
                !signature
                    .fast_aggregate_verify(&key_refs[..4], message)
                    .unwrap()
            );
            assert!(signatures[0].verify(&public_keys[0], message).unwrap());
        }
    }

    #[test]
    fn prewarmed_keys_verify_and_invalid_keys_are_skipped() {
        let message = b"sync committee root";
        let private_keys: Vec<PrivateKey> = (40..44).map(private_key).collect();
        let public_keys: Vec<PublicKey> = private_keys
            .iter()
            .map(|key| key.public_key().unwrap())
            .collect();
        let invalid = PublicKey {
            inner: FixedBytes::repeat_byte(0x8a),
        };
        let mut to_prewarm = public_keys.clone();
        to_prewarm.push(invalid);
        assert_eq!(prewarm_public_keys(&to_prewarm), public_keys.len());
        // Already cached keys are not decompressed again.
        assert_eq!(prewarm_public_keys(&public_keys), 0);

        let signatures: Vec<BLSSignature> = private_keys
            .iter()
            .map(|key| key.sign(message).unwrap())
            .collect();
        let signature = BLSSignature::aggregate(&signatures.iter().collect::<Vec<_>>()).unwrap();
        let key_refs: Vec<&PublicKey> = public_keys.iter().collect();
        assert!(signature.fast_aggregate_verify(&key_refs, message).unwrap());
    }

    #[test]
    fn large_aggregates_sum_in_parallel_like_one_thread() {
        // Repeat a few distinct keys past the parallel threshold, with one key left uncached.
        let keys: Vec<PublicKey> = (60..64)
            .map(|index| private_key(index).public_key().unwrap())
            .collect();
        prewarm_public_keys(&keys[..3]);
        let refs: Vec<&PublicKey> = keys
            .iter()
            .cycle()
            .take(PARALLEL_AGGREGATION_THRESHOLD + 7)
            .collect();
        let sequential = sum_public_keys(&refs).unwrap();
        assert_eq!(aggregate_public_key_point(&refs).unwrap(), sequential);

        let invalid = PublicKey {
            inner: FixedBytes::repeat_byte(0x8a),
        };
        let mut with_invalid = refs.clone();
        with_invalid.push(&invalid);
        assert!(aggregate_public_key_point(&with_invalid).is_err());
    }

    #[test]
    fn invalid_keys_are_rejected_every_time() {
        let invalid = PublicKey {
            inner: FixedBytes::repeat_byte(0x8a),
        };
        for _ in 0..2 {
            assert!(decompress_public_key(&invalid).is_err());
            assert!(PublicKey::aggregate(&[&invalid]).is_err());
        }
    }
}

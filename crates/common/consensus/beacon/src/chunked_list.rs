use std::{
    fmt,
    marker::PhantomData,
    ops::{Index, IndexMut},
    sync::Arc,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode, SszEncoder};
use ssz_types::{VariableList, typenum::Unsigned};
use tree_hash::{Hash256, PackedEncoding, TreeHash, TreeHashType};
#[cfg(not(feature = "zkvm"))]
use tree_hash::{MerkleHasher, mix_in_length};

/// Elements per chunk. Mainnet's validator registry of about 2.4 million validators is then about
/// 2,300 chunks of 128 KiB.
pub(crate) const CHUNK_SIZE: usize = 1024;

/// An SSZ list of at most `N` elements, stored as chunks behind `Arc`s. It encodes, decodes and
/// hashes exactly like `VariableList<T, N>`.
///
/// Copying the list copies only the chunk pointers, and changing an element copies its chunk
/// first when another list shares that chunk. Mainnet's validator registry is about 300 MB and most
/// blocks change a few validators, so copying a state no longer copies the registry, and states a
/// few blocks apart share all but a few chunks.
pub struct ChunkedList<T, N> {
    /// Every chunk holds `CHUNK_SIZE` elements except the last, which holds at least one.
    chunks: Vec<Arc<Vec<T>>>,
    len: usize,
    _limit: PhantomData<N>,
}

/// Iterator over the elements of a [`ChunkedList`].
pub struct Iter<'a, T> {
    chunks: &'a [Arc<Vec<T>>],
    /// Index of the next element from the front.
    front: usize,
    /// One past the index of the next element from the back.
    back: usize,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        let element = &self.chunks[self.front / CHUNK_SIZE][self.front % CHUNK_SIZE];
        self.front += 1;
        Some(element)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.back - self.front;
        (remaining, Some(remaining))
    }
}

impl<T> DoubleEndedIterator for Iter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        self.back -= 1;
        Some(&self.chunks[self.back / CHUNK_SIZE][self.back % CHUNK_SIZE])
    }
}

impl<T> ExactSizeIterator for Iter<'_, T> {}

impl<T, N> ChunkedList<T, N> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        Some(&self.chunks[index / CHUNK_SIZE][index % CHUNK_SIZE])
    }

    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            chunks: &self.chunks,
            front: 0,
            back: self.len,
        }
    }

    /// The chunks, each `CHUNK_SIZE` elements long except the last.
    pub(crate) fn chunks(&self) -> &[Arc<Vec<T>>] {
        &self.chunks
    }
}

impl<T: Clone, N: Unsigned> ChunkedList<T, N> {
    pub fn new(elements: Vec<T>) -> Result<Self, ssz_types::Error> {
        if elements.len() > N::to_usize() {
            return Err(ssz_types::Error::OutOfBounds {
                i: elements.len(),
                len: N::to_usize(),
            });
        }
        Ok(Self::from_vec(elements))
    }

    fn from_vec(elements: Vec<T>) -> Self {
        let len = elements.len();
        let chunks = elements
            .chunks(CHUNK_SIZE)
            .map(|chunk| Arc::new(chunk.to_vec()))
            .collect();
        Self {
            chunks,
            len,
            _limit: PhantomData,
        }
    }

    /// The element at `index`, copying its chunk first if another list shares it.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }
        Some(&mut Arc::make_mut(&mut self.chunks[index / CHUNK_SIZE])[index % CHUNK_SIZE])
    }

    /// Every element mutably, copying each chunk that another list shares.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.chunks
            .iter_mut()
            .flat_map(|chunk| Arc::make_mut(chunk).iter_mut())
    }

    pub fn push(&mut self, element: T) -> Result<(), ssz_types::Error> {
        if self.len >= N::to_usize() {
            return Err(ssz_types::Error::OutOfBounds {
                i: self.len,
                len: N::to_usize(),
            });
        }
        match self.chunks.last_mut() {
            Some(chunk) if chunk.len() < CHUNK_SIZE => Arc::make_mut(chunk).push(element),
            _ => {
                let mut chunk = Vec::with_capacity(CHUNK_SIZE);
                chunk.push(element);
                self.chunks.push(Arc::new(chunk));
            }
        }
        self.len += 1;
        Ok(())
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.iter().cloned().collect()
    }
}

impl<T, N> Clone for ChunkedList<T, N> {
    fn clone(&self) -> Self {
        Self {
            chunks: self.chunks.clone(),
            len: self.len,
            _limit: PhantomData,
        }
    }
}

impl<T, N> Default for ChunkedList<T, N> {
    fn default() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
            _limit: PhantomData,
        }
    }
}

impl<T: PartialEq, N> PartialEq for ChunkedList<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self
                .chunks
                .iter()
                .zip(&other.chunks)
                .all(|(chunk, other)| Arc::ptr_eq(chunk, other) || chunk == other)
    }
}

impl<T: Eq, N> Eq for ChunkedList<T, N> {}

impl<T: fmt::Debug, N> fmt::Debug for ChunkedList<T, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

impl<T, N> Index<usize> for ChunkedList<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        self.get(index).expect("index is within the list")
    }
}

/// Copies the element's chunk first if another list shares it.
impl<T: Clone, N: Unsigned> IndexMut<usize> for ChunkedList<T, N> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        self.get_mut(index).expect("index is within the list")
    }
}

impl<'a, T, N> IntoIterator for &'a ChunkedList<T, N> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: Clone, N: Unsigned> From<VariableList<T, N>> for ChunkedList<T, N> {
    fn from(list: VariableList<T, N>) -> Self {
        Self::from_vec(list.into())
    }
}

impl<T: Encode, N> Encode for ChunkedList<T, N> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        if T::is_ssz_fixed_len() {
            self.len * T::ssz_fixed_len()
        } else {
            self.iter()
                .map(|element| element.ssz_bytes_len() + BYTES_PER_LENGTH_OFFSET)
                .sum()
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if T::is_ssz_fixed_len() {
            buf.reserve(self.len * T::ssz_fixed_len());
            for element in self.iter() {
                element.ssz_append(buf);
            }
        } else {
            let mut encoder = SszEncoder::container(buf, self.len * BYTES_PER_LENGTH_OFFSET);
            for element in self.iter() {
                encoder.append(element);
            }
            encoder.finalize();
        }
    }
}

impl<T: Decode + Clone + 'static, N: Unsigned> Decode for ChunkedList<T, N> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        VariableList::<T, N>::from_ssz_bytes(bytes).map(Self::from)
    }
}

/// The same root as `VariableList<T, N>`.
impl<T: TreeHash + Clone, N: Unsigned> TreeHash for ChunkedList<T, N> {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    /// zkVM builds use a patched `VariableList` that hashes its 2^29 limit as 2^40, so they hash
    /// through it to get the same root.
    #[cfg(feature = "zkvm")]
    fn tree_hash_root(&self) -> Hash256 {
        VariableList::<T, N>::new(self.to_vec())
            .expect("the list holds at most N elements")
            .tree_hash_root()
    }

    #[cfg(not(feature = "zkvm"))]
    fn tree_hash_root(&self) -> Hash256 {
        let root = match T::tree_hash_type() {
            TreeHashType::Basic => {
                let mut hasher = MerkleHasher::with_leaves(
                    N::to_usize().div_ceil(T::tree_hash_packing_factor()),
                );
                for element in self.iter() {
                    hasher
                        .write(&element.tree_hash_packed_encoding())
                        .expect("the list holds at most N elements");
                }
                hasher.finish().expect("no bytes are left over")
            }
            TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => {
                let mut hasher = MerkleHasher::with_leaves(N::to_usize());
                for element in self.iter() {
                    hasher
                        .write(element.tree_hash_root().as_slice())
                        .expect("the list holds at most N elements");
                }
                hasher.finish().expect("no bytes are left over")
            }
        };
        mix_in_length(&root, self.len)
    }
}

impl<T: Serialize, N> Serialize for ChunkedList<T, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl<'de, T: Deserialize<'de> + Clone, N: Unsigned> Deserialize<'de> for ChunkedList<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Vec::deserialize(deserializer)?)
            .map_err(|err| serde::de::Error::custom(format!("{err:?}")))
    }
}

#[cfg(test)]
mod tests {
    use ssz_types::typenum::U4096;

    use super::*;

    fn list_of(len: u64) -> (ChunkedList<u64, U4096>, VariableList<u64, U4096>) {
        let elements: Vec<u64> = (0..len).map(|value| value * 7 + 1).collect();
        (
            ChunkedList::new(elements.clone()).unwrap(),
            VariableList::new(elements).unwrap(),
        )
    }

    #[test]
    fn encodes_decodes_and_hashes_like_a_variable_list() {
        for len in [0, 1, CHUNK_SIZE as u64 - 1, CHUNK_SIZE as u64, 2500] {
            let (chunked, plain) = list_of(len);
            assert_eq!(chunked.as_ssz_bytes(), plain.as_ssz_bytes());
            assert_eq!(chunked.tree_hash_root(), plain.tree_hash_root());
            assert_eq!(
                ChunkedList::<u64, U4096>::from_ssz_bytes(&plain.as_ssz_bytes()).unwrap(),
                chunked
            );
            assert_eq!(
                serde_json::to_string(&chunked).unwrap(),
                serde_json::to_string(&plain).unwrap()
            );
            assert_eq!(chunked.iter().len(), len as usize);
        }
    }

    #[test]
    fn copies_share_chunks_until_one_changes() {
        let (original, _) = list_of(2500);
        let mut copy = original.clone();
        copy[1500] = 0;
        copy.push(9).unwrap();

        assert_eq!(original[1500], 1500 * 7 + 1);
        assert_eq!(copy[1500], 0);
        assert_eq!((original.len(), copy.len()), (2500, 2501));
        // Only the changed chunk and the extended last chunk were copied.
        let shared = original
            .chunks()
            .iter()
            .zip(copy.chunks())
            .filter(|(chunk, other)| Arc::ptr_eq(chunk, other))
            .count();
        assert_eq!(shared, 1);
        assert_ne!(original, copy);
    }

    #[test]
    fn refuses_more_than_the_limit() {
        assert!(ChunkedList::<u64, U4096>::new(vec![0; 4097]).is_err());
        let (mut full, _) = list_of(4096);
        assert!(full.push(0).is_err());
    }
}

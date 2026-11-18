//! https://ethereum.github.io/consensus-specs/ssz/merkle-proofs

pub mod multiproof;

use alloy_primitives::B256;
use anyhow::ensure;
use tree_hash::MerkleHasher;

mod hash;
mod index;

use hash::hash_concat;
use index::{generalized_index_child, get_generalized_index_bit, get_subtree_index};

pub fn merkle_tree(leaves: &[B256], depth: u64) -> anyhow::Result<Vec<B256>> {
    let num_of_leaves = leaves.len();
    let bottom_length = 1 << depth;
    ensure!(
        num_of_leaves <= bottom_length,
        "Number of leaves is greater than the bottom length (depth too small)"
    );

    let mut tree = vec![B256::ZERO; bottom_length];
    tree.extend(leaves);
    tree.extend(vec![B256::ZERO; bottom_length - num_of_leaves]);

    for i in (1..bottom_length).rev() {
        let left = tree[i * 2].as_slice();
        let right = tree[i * 2 + 1].as_slice();
        tree[i] = hash_concat(left, right);
    }

    Ok(tree)
}

pub fn generate_proof(tree: &[B256], index: u64, depth: u64) -> anyhow::Result<Vec<B256>> {
    let bottom_length = 1 << depth;
    ensure!(index < bottom_length, "Index out of bounds");

    let mut proof = vec![];
    let mut current_index = 1;
    let mut current_depth = depth;

    while current_depth > 0 {
        let (left_child_index, right_child_index) = (
            generalized_index_child(current_index, false),
            generalized_index_child(current_index, true),
        );

        if get_generalized_index_bit(index, current_depth - 1) {
            proof.push(tree[left_child_index as usize]);
            current_index = right_child_index;
        } else {
            proof.push(tree[right_child_index as usize]);
            current_index = left_child_index;
        }

        current_depth -= 1;
    }

    proof.reverse();

    Ok(proof)
}

pub fn is_valid_merkle_branch(
    leaf: B256,
    branch: &[B256],
    depth: u64,
    index: u64,
    root: B256,
) -> bool {
    if branch.len() != depth as usize {
        return false;
    }
    root == get_root_from_merkle_branch(leaf, branch, depth, index)
}

pub fn get_root_from_merkle_branch(leaf: B256, branch: &[B256], depth: u64, index: u64) -> B256 {
    let mut value = leaf;
    for i in 0..depth {
        if get_generalized_index_bit(index, i) {
            value = hash_concat(branch[i as usize].as_slice(), value.as_slice());
        } else {
            value = hash_concat(value.as_slice(), branch[i as usize].as_slice());
        }
    }
    value
}

pub fn is_valid_normalized_merkle_branch(
    leaf: B256,
    branch: &[B256],
    generalized_index: u64,
    root: B256,
) -> bool {
    let depth = (generalized_index as f64).log2().floor() as u64;
    let index = get_subtree_index(generalized_index);
    if branch.len() < depth as usize {
        return false;
    }
    let num_extra = branch.len() - depth as usize;
    for node in branch[..num_extra].iter() {
        if *node != B256::ZERO {
            return false;
        }
    }
    is_valid_merkle_branch(leaf, &branch[num_extra..], depth, index, root)
}

/// Root of a progressive Merkle tree: binary subtrees of 1, 4, 16, ... leaves hang off a
/// zero-terminated spine. https://eips.ethereum.org/EIPS/eip-7916#progressive-merkle-tree
pub fn merkleize_progressive(chunks: &[B256]) -> B256 {
    merkleize_progressive_from(chunks, 1)
}

fn merkleize_progressive_from(chunks: &[B256], num_leaves: usize) -> B256 {
    if chunks.is_empty() {
        return B256::ZERO;
    }
    let (subtree, rest) = chunks.split_at(chunks.len().min(num_leaves));
    let mut hasher = MerkleHasher::with_leaves(num_leaves);
    for chunk in subtree {
        hasher
            .write(chunk.as_slice())
            .expect("subtree has at most num_leaves chunks");
    }
    let left = hasher
        .finish()
        .expect("subtree has at most num_leaves chunks");
    let right = merkleize_progressive_from(rest, num_leaves * 4);
    hash_concat(left.as_slice(), right.as_slice())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::b256;

    use super::*;

    #[test]
    fn test_merkle_tree() {
        let leaves = vec![
            B256::from_slice(&[0xAA; 32]),
            B256::from_slice(&[0xBB; 32]),
            B256::from_slice(&[0xCC; 32]),
            B256::from_slice(&[0xDD; 32]),
        ];

        let depth = (leaves.len() as f64).log2().ceil() as u64;

        let node_2 = hash_concat(leaves[0].as_slice(), leaves[1].as_slice());
        let node_3 = hash_concat(leaves[2].as_slice(), leaves[3].as_slice());

        let root = hash_concat(node_2.as_slice(), node_3.as_slice());

        let tree = merkle_tree(&leaves, depth).unwrap();

        assert_eq!(tree[1], root);

        let proof_0 = generate_proof(&tree, 0, depth).unwrap();
        let proof_1 = generate_proof(&tree, 1, depth).unwrap();
        let proof_2 = generate_proof(&tree, 2, depth).unwrap();
        let proof_3 = generate_proof(&tree, 3, depth).unwrap();

        assert!(is_valid_merkle_branch(leaves[0], &proof_0, depth, 0, root));
        assert!(is_valid_merkle_branch(leaves[1], &proof_1, depth, 1, root));
        assert!(is_valid_merkle_branch(leaves[2], &proof_2, depth, 2, root));
        assert!(is_valid_merkle_branch(leaves[3], &proof_3, depth, 3, root));

        assert!(is_valid_normalized_merkle_branch(
            leaves[0],
            &proof_0,
            1 << depth,
            root
        ));
        assert!(is_valid_normalized_merkle_branch(
            leaves[1],
            &proof_1,
            (1 << depth) + 1,
            root
        ));
        assert!(is_valid_normalized_merkle_branch(
            leaves[2],
            &proof_2,
            (1 << depth) + 2,
            root
        ));
        assert!(is_valid_normalized_merkle_branch(
            leaves[3],
            &proof_3,
            (1 << depth) + 3,
            root
        ));
    }

    /// Expected roots come from a Python copy of the spec `merkleize` and EIP-7916
    /// `merkleize_progressive` (sha256, zero-padded subtrees); chunk `i` is `[i + 1; 32]`.
    #[test]
    fn test_merkleize_progressive() {
        let lens = [0, 1, 2, 5, 6, 21, 22, 85, 86];
        let roots = [
            b256!("0000000000000000000000000000000000000000000000000000000000000000"),
            b256!("037d6dfb3a369a41e01100fdd53c35ee3fb69ddec5830d61e1138d066a4c2285"),
            b256!("2dfe47da19ad9ff11afe44dd8de4db8517cefd5a9bddffe6652b26a1b91ea5ac"),
            b256!("3fd53b812118ddea60b9deab5c72d32b0c4dcfd2c94deda753e6e1d548fbc274"),
            b256!("2e2a2abd4d0e28498ec0cdd817c715b246aa15e7b34767061b7632337188429e"),
            b256!("f148f679afbfebfe5616080a45461aee3d1f4ce2cc752ce824c3f067d2707623"),
            b256!("040be60071c540aafc1d44f366239ab6a41bf8740a38f9d52ab0bbd9cd974c45"),
            b256!("24ea21562226364be74fd2696d0824a4347cfac7dd4b2ae28cd0e9cc22bc341d"),
            b256!("b73c4c427974f47c74c2812d353c966f5dadae70c44f6fe9a15e179b86914977"),
        ];
        for (len, expected) in lens.into_iter().zip(roots) {
            let chunks: Vec<B256> = (0..len).map(|i| B256::repeat_byte(i as u8 + 1)).collect();
            assert_eq!(merkleize_progressive(&chunks), expected, "{len} chunks");
        }
    }
}

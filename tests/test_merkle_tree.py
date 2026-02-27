"""Tests for the Merkle tree builder and proof verification.

ISO 16363 section 5.2.2, section 5.2.3.
"""

from __future__ import annotations

import hashlib

import pytest

from guardian.services.merkle_tree import MerkleTree, MerkleTreeBuilder


# -------------------------------------------------------------------------
# 1. test_build_single_hash
# -------------------------------------------------------------------------

class TestBuildSingleHash:
    def test_build_single_hash(self) -> None:
        """A tree built from a single hash should have that hash as the root."""
        leaf = hashlib.sha256(b"record_1").hexdigest()
        tree = MerkleTreeBuilder.build([leaf])

        assert tree.root == leaf
        assert tree.leaves == [leaf]
        assert len(tree.levels) == 1


# -------------------------------------------------------------------------
# 2. test_build_multiple_hashes
# -------------------------------------------------------------------------

class TestBuildMultipleHashes:
    def test_build_multiple_hashes(self) -> None:
        """A tree built from multiple hashes should produce a deterministic root."""
        hashes = [hashlib.sha256(f"record_{i}".encode()).hexdigest() for i in range(5)]
        tree = MerkleTreeBuilder.build(hashes)

        assert tree.root != ""
        assert len(tree.root) == 64
        assert tree.leaves == hashes
        # There should be multiple levels: leaves -> intermediate -> root.
        assert len(tree.levels) > 1

    def test_deterministic(self) -> None:
        """Building the same tree twice should produce the same root."""
        hashes = [hashlib.sha256(f"record_{i}".encode()).hexdigest() for i in range(7)]
        tree1 = MerkleTreeBuilder.build(hashes)
        tree2 = MerkleTreeBuilder.build(hashes)

        assert tree1.root == tree2.root

    def test_empty_raises(self) -> None:
        """Building a tree from an empty list should raise ValueError."""
        with pytest.raises(ValueError, match="empty"):
            MerkleTreeBuilder.build([])


# -------------------------------------------------------------------------
# 3. test_build_power_of_two
# -------------------------------------------------------------------------

class TestBuildPowerOfTwo:
    def test_build_power_of_two(self) -> None:
        """A tree built from a power-of-two number of leaves should not need
        padding and should have the expected number of levels."""
        hashes = [hashlib.sha256(f"record_{i}".encode()).hexdigest() for i in range(8)]
        tree = MerkleTreeBuilder.build(hashes)

        assert tree.root != ""
        assert tree.leaves == hashes
        # 8 leaves -> 4 level-1 -> 2 level-2 -> 1 root = 4 levels.
        assert len(tree.levels) == 4
        assert len(tree.levels[0]) == 8  # Leaf level (no padding needed).

    def test_non_power_of_two_pads(self) -> None:
        """A tree built from a non-power-of-two count should pad the leaf level."""
        hashes = [hashlib.sha256(f"record_{i}".encode()).hexdigest() for i in range(3)]
        tree = MerkleTreeBuilder.build(hashes)

        # 3 leaves should be padded to 4.
        assert len(tree.levels[0]) == 4
        # The padding element should duplicate the last hash.
        assert tree.levels[0][3] == tree.levels[0][2]


# -------------------------------------------------------------------------
# 4. test_proof_generation
# -------------------------------------------------------------------------

class TestProofGeneration:
    def test_proof_generation(self) -> None:
        """get_proof should return a non-empty proof path for any valid leaf index."""
        hashes = [hashlib.sha256(f"record_{i}".encode()).hexdigest() for i in range(8)]
        tree = MerkleTreeBuilder.build(hashes)

        for idx in range(len(hashes)):
            proof = MerkleTreeBuilder.get_proof(tree, idx)
            assert len(proof) > 0
            for sibling_hash, position in proof:
                assert len(sibling_hash) == 64
                assert position in ("left", "right")

    def test_proof_out_of_range(self) -> None:
        """get_proof should raise IndexError for an invalid leaf index."""
        hashes = [hashlib.sha256(b"x").hexdigest()]
        tree = MerkleTreeBuilder.build(hashes)

        with pytest.raises(IndexError):
            MerkleTreeBuilder.get_proof(tree, 5)

        with pytest.raises(IndexError):
            MerkleTreeBuilder.get_proof(tree, -1)


# -------------------------------------------------------------------------
# 5. test_proof_verification
# -------------------------------------------------------------------------

class TestProofVerification:
    def test_proof_verification(self) -> None:
        """A valid proof should verify against the tree root."""
        hashes = [hashlib.sha256(f"record_{i}".encode()).hexdigest() for i in range(8)]
        tree = MerkleTreeBuilder.build(hashes)

        for idx in range(len(hashes)):
            proof = MerkleTreeBuilder.get_proof(tree, idx)
            assert MerkleTreeBuilder.verify_proof(hashes[idx], proof, tree.root) is True

    def test_proof_verification_non_power_of_two(self) -> None:
        """Proofs should also verify for non-power-of-two leaf counts."""
        hashes = [hashlib.sha256(f"record_{i}".encode()).hexdigest() for i in range(5)]
        tree = MerkleTreeBuilder.build(hashes)

        for idx in range(len(hashes)):
            proof = MerkleTreeBuilder.get_proof(tree, idx)
            assert MerkleTreeBuilder.verify_proof(hashes[idx], proof, tree.root) is True


# -------------------------------------------------------------------------
# 6. test_invalid_proof
# -------------------------------------------------------------------------

class TestInvalidProof:
    def test_invalid_proof_wrong_root(self) -> None:
        """A proof verified against the wrong root should return False."""
        hashes = [hashlib.sha256(f"record_{i}".encode()).hexdigest() for i in range(4)]
        tree = MerkleTreeBuilder.build(hashes)

        proof = MerkleTreeBuilder.get_proof(tree, 0)
        wrong_root = "0" * 64

        assert MerkleTreeBuilder.verify_proof(hashes[0], proof, wrong_root) is False

    def test_invalid_proof_wrong_leaf(self) -> None:
        """A proof verified with a wrong leaf hash should return False."""
        hashes = [hashlib.sha256(f"record_{i}".encode()).hexdigest() for i in range(4)]
        tree = MerkleTreeBuilder.build(hashes)

        proof = MerkleTreeBuilder.get_proof(tree, 0)
        wrong_leaf = hashlib.sha256(b"WRONG").hexdigest()

        assert MerkleTreeBuilder.verify_proof(wrong_leaf, proof, tree.root) is False

    def test_invalid_proof_tampered_sibling(self) -> None:
        """A proof with a tampered sibling hash should return False."""
        hashes = [hashlib.sha256(f"record_{i}".encode()).hexdigest() for i in range(4)]
        tree = MerkleTreeBuilder.build(hashes)

        proof = MerkleTreeBuilder.get_proof(tree, 0)
        # Tamper with the first sibling in the proof.
        if proof:
            tampered_proof = [("0" * 64, proof[0][1])] + proof[1:]
            assert MerkleTreeBuilder.verify_proof(
                hashes[0], tampered_proof, tree.root
            ) is False

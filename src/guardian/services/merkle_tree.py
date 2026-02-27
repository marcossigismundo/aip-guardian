"""Merkle tree construction and proof verification.

Provides a complete Merkle tree implementation for batching audit log
record hashes before submitting them to an RFC 3161 TSA.  Each leaf is
an existing hex-encoded SHA-256 hash; internal nodes are computed as
``SHA-256(left || right)``.

ISO 16363 §5.2.2, §5.2.3
"""

from __future__ import annotations

import hashlib
import logging
import math
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class MerkleTree:
    """Immutable representation of a complete Merkle tree."""

    root: str
    """Hex-encoded SHA-256 root hash."""

    leaves: list[str]
    """Original (un-padded) leaf hashes in insertion order."""

    levels: list[list[str]] = field(repr=False)
    """All tree levels from leaves (index 0) up to root (last index)."""


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class MerkleTreeBuilder:
    """Construct a Merkle tree from a list of hex-encoded SHA-256 hashes.

    The builder pads the leaf list to the next power of two by duplicating
    the last leaf so that every internal node has exactly two children.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def build(hashes: list[str]) -> MerkleTree:
        """Build a full Merkle tree from *hashes*.

        Parameters
        ----------
        hashes:
            Non-empty list of hex-encoded SHA-256 hashes (the leaves).

        Returns
        -------
        MerkleTree
            A frozen dataclass containing the root, original leaves,
            and every intermediate level.

        Raises
        ------
        ValueError
            If *hashes* is empty.
        """
        if not hashes:
            raise ValueError("Cannot build a Merkle tree from an empty list of hashes.")

        # Keep a copy of the original leaves before padding.
        original_leaves = list(hashes)

        # Pad to the next power of two by duplicating the last element.
        padded = list(hashes)
        target_size = 1 << math.ceil(math.log2(len(padded))) if len(padded) > 1 else 1
        while len(padded) < target_size:
            padded.append(padded[-1])

        levels: list[list[str]] = [padded]

        current_level = padded
        while len(current_level) > 1:
            next_level: list[str] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]
                parent = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(parent)
            levels.append(next_level)
            current_level = next_level

        root = current_level[0]

        logger.debug(
            "Built Merkle tree: %d leaves (padded to %d), root=%s",
            len(original_leaves),
            len(padded),
            root,
        )

        return MerkleTree(root=root, leaves=original_leaves, levels=levels)

    # ------------------------------------------------------------------

    @staticmethod
    def get_proof(tree: MerkleTree, leaf_index: int) -> list[tuple[str, str]]:
        """Return an inclusion proof for the leaf at *leaf_index*.

        The proof is a list of ``(sibling_hash, position)`` tuples where
        *position* is ``"left"`` or ``"right"`` indicating which side the
        sibling sits on relative to the path element.

        Parameters
        ----------
        tree:
            A previously built :class:`MerkleTree`.
        leaf_index:
            Zero-based index into ``tree.leaves``.

        Returns
        -------
        list[tuple[str, str]]
            Ordered bottom-to-top proof path.

        Raises
        ------
        IndexError
            If *leaf_index* is out of range.
        """
        if leaf_index < 0 or leaf_index >= len(tree.leaves):
            raise IndexError(
                f"leaf_index {leaf_index} out of range for tree with "
                f"{len(tree.leaves)} leaves."
            )

        proof: list[tuple[str, str]] = []
        idx = leaf_index

        for level in tree.levels[:-1]:  # skip root level
            if idx % 2 == 0:
                sibling_idx = idx + 1
                position = "right"
            else:
                sibling_idx = idx - 1
                position = "left"

            if sibling_idx < len(level):
                proof.append((level[sibling_idx], position))

            # Move up to the parent index.
            idx //= 2

        return proof

    # ------------------------------------------------------------------

    @staticmethod
    def verify_proof(leaf_hash: str, proof: list[tuple[str, str]], root_hash: str) -> bool:
        """Verify that *leaf_hash* belongs to a tree with *root_hash*.

        Parameters
        ----------
        leaf_hash:
            The hex-encoded SHA-256 hash of the leaf to verify.
        proof:
            The inclusion proof as returned by :meth:`get_proof`.
        root_hash:
            The expected Merkle root.

        Returns
        -------
        bool
            ``True`` if the proof is valid, ``False`` otherwise.
        """
        current = leaf_hash
        for sibling_hash, position in proof:
            if position == "left":
                combined = sibling_hash + current
            else:
                combined = current + sibling_hash
            current = hashlib.sha256(combined.encode()).hexdigest()

        is_valid = current == root_hash
        if not is_valid:
            logger.warning(
                "Merkle proof verification failed: computed root %s != expected %s",
                current,
                root_hash,
            )
        return is_valid

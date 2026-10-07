// SPDX-License-Identifier: GPL-3.0-only
//
// Small, fast, non-cryptographic hasher (the "Fx" family used by rustc).
//
// The hard-link set and the various id maps are keyed by integers that we
// generated ourselves, so SipHash's DoS resistance buys nothing here while its
// cost shows up in a scan that does one set operation per multiply-linked
// inode.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

#[derive(Clone, Copy, Default)]
pub struct FxHasher {
    hash: u64,
}

impl FxHasher {
    #[inline]
    pub fn with_seed(seed: u64) -> Self {
        Self { hash: seed }
    }

    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let (chunks, rest) = bytes.as_chunks::<8>();
        for chunk in chunks {
            self.add(u64::from_le_bytes(*chunk));
        }
        if !rest.is_empty() {
            let mut buf = [0u8; 8];
            buf[..rest.len()].copy_from_slice(rest);
            // Mix the length in so "a" and "a\0" differ.
            self.add(u64::from_le_bytes(buf) ^ ((rest.len() as u64) << 56));
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(u64::from(i));
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(u64::from(i));
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(u64::from(i));
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        // hashbrown uses the top bits for its control bytes; a final rotate
        // keeps the well-mixed bits where both halves can see them.
        self.hash.rotate_left(26)
    }
}

pub type FxBuildHasher = BuildHasherDefault<FxHasher>;
pub type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;
pub type FxHashSet<K> = HashSet<K, FxBuildHasher>;

/// Chain a path component into a running path hash. The hash of a path is the
/// fold of this function over its components, so it can be maintained
/// incrementally during a DFS (O(1) per directory) and also recomputed from a
/// plain path string.
#[inline]
pub fn mix_component(parent: u64, name: &[u8]) -> u64 {
    let mut h = FxHasher::with_seed(parent);
    h.write(name);
    h.write_u8(b'/');
    h.finish()
}

/// Hash an absolute path the same way the scanner hashes directory nodes.
pub fn hash_path_bytes(path: &[u8]) -> u64 {
    path.split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .fold(0u64, mix_component)
}

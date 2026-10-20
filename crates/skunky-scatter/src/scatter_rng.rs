// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BingoCube-backed PRNG for the scatter server.
//!
//! `CubePrng` replaces hand-rolled XorShift64 with BLAKE3-derived entropy
//! from BingoCube scalar fields. Same API, crypto-grade mixing.
//!
//! Each cube provides 25 BLAKE3-derived u64 values (5x5 scalar field).
//! Once exhausted, the cube chains forward: the current cube's hash seeds
//! the next cube, giving an infinite deterministic stream from a single seed.
//!
//! Same seed -> same output, always. Fleet scrapers that request the same
//! path twice get identical poison, preventing detection via request diffing.

#![allow(missing_docs)]

use bingocube_core::{BingoCube, Config};

/// BingoCube-backed deterministic PRNG for scatter content generation.
///
/// Replaces XorShift64 with BLAKE3-derived entropy. Each 5x5 cube provides
/// 25 scalar field values; when exhausted, chains to the next cube
/// via BLAKE3 re-seeding. Deterministic for the same seed.
pub struct CubePrng {
    /// Current cube's scalar values, flattened row-major.
    scalars: Vec<u64>,
    /// Index into the current scalars buffer.
    cursor: usize,
    /// Chain seed for generating the next cube.
    chain_seed: Vec<u8>,
    /// How many cubes deep we've chained.
    generation: u64,
}

/// BingoCube config for scatter PRNG: 5x5, no free cell (all 25 cells usable).
fn prng_config() -> Config {
    Config {
        grid_size: 5,
        universe_size: 100,
        palette_size: 16,
        free_cell: None,
    }
}

impl CubePrng {
    /// Create a new PRNG from a u64 seed.
    pub fn new(seed: u64) -> Self {
        let seed = if seed == 0 { 1 } else { seed };
        let seed_bytes = seed.to_le_bytes();
        Self::from_bytes(&seed_bytes)
    }

    /// Create a new PRNG from arbitrary seed bytes.
    pub fn from_bytes(seed: &[u8]) -> Self {
        let cube = BingoCube::from_seed(seed, prng_config())
            .expect("prng_config is always valid");
        let scalars = Self::extract_scalars(&cube);
        Self {
            scalars,
            cursor: 0,
            chain_seed: seed.to_vec(),
            generation: 0,
        }
    }

    /// Extract all scalar field values from a cube as a flat Vec.
    fn extract_scalars(cube: &BingoCube) -> Vec<u64> {
        let size = cube.config.grid_size;
        let mut out = Vec::with_capacity(size * size);
        for row in 0..size {
            for col in 0..size {
                out.push(cube.get_scalar(row, col).unwrap_or(0));
            }
        }
        out
    }

    /// Chain to the next cube when current scalars are exhausted.
    fn chain_next(&mut self) {
        self.generation += 1;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CUBEPRNG_CHAIN");
        hasher.update(&self.chain_seed);
        hasher.update(&self.generation.to_le_bytes());
        let hash = hasher.finalize();
        self.chain_seed = hash.as_bytes()[..16].to_vec();

        let cube = BingoCube::from_seed(&self.chain_seed, prng_config())
            .expect("prng_config is always valid");
        self.scalars = Self::extract_scalars(&cube);
        self.cursor = 0;
    }

    pub fn next_u64(&mut self) -> u64 {
        if self.cursor >= self.scalars.len() {
            self.chain_next();
        }
        let val = self.scalars[self.cursor];
        self.cursor += 1;
        val
    }

    pub fn next_usize(&mut self) -> usize {
        self.next_u64() as usize
    }

    pub fn hex(&mut self, len: usize) -> String {
        let mut s = String::with_capacity(len);
        while s.len() < len {
            s.push_str(&format!("{:016x}", self.next_u64()));
        }
        s.truncate(len);
        s
    }

    pub fn alphanum(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| CHARSET[self.next_usize() % CHARSET.len()] as char)
            .collect()
    }

    pub fn upper_alphanum(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| CHARSET[self.next_usize() % CHARSET.len()] as char)
            .collect()
    }

    pub fn base64ish(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        (0..len)
            .map(|_| CHARSET[self.next_usize() % CHARSET.len()] as char)
            .collect()
    }
}

/// Backward-compatible alias. All call sites use this name today.
pub(crate) type XorShift64 = CubePrng;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_seed() {
        let mut a = CubePrng::new(42);
        let mut b = CubePrng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_differ() {
        let mut a = CubePrng::new(42);
        let mut b = CubePrng::new(99);
        let mut same = 0;
        for _ in 0..25 {
            if a.next_u64() == b.next_u64() {
                same += 1;
            }
        }
        assert!(same < 3, "different seeds should produce different streams");
    }

    #[test]
    fn chains_past_25_values() {
        let mut rng = CubePrng::new(1);
        let mut vals = Vec::new();
        for _ in 0..60 {
            vals.push(rng.next_u64());
        }
        assert_eq!(vals.len(), 60);
        assert_eq!(rng.generation, 2);
    }

    #[test]
    fn zero_seed_handled() {
        let mut rng = CubePrng::new(0);
        let v = rng.next_u64();
        assert_ne!(v, 0);
    }

    #[test]
    fn hex_length_correct() {
        let mut rng = CubePrng::new(7);
        assert_eq!(rng.hex(40).len(), 40);
        assert_eq!(rng.hex(8).len(), 8);
        assert_eq!(rng.hex(1).len(), 1);
    }

    #[test]
    fn alphanum_charset_valid() {
        let mut rng = CubePrng::new(7);
        let s = rng.alphanum(100);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn from_bytes_deterministic() {
        let mut a = CubePrng::from_bytes(b"scatter:fleet:abc123");
        let mut b = CubePrng::from_bytes(b"scatter:fleet:abc123");
        for _ in 0..50 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}

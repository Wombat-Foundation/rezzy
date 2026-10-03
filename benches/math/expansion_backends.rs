//! Experimental LtHash expansion backends: a hand-rolled SHA-512 CTR XOF and
//! an AES-256-CTR XOF (AES-NI or portable T-tables), measured beside the
//! shipped BLAKE3 XOF and MSC4500's SHAKE256.
//!
//! # Not wire-compatible
//!
//! MSC4500 expands each element with SHAKE256 under `msc4500:lthash16:v1`;
//! rezzy ships BLAKE3 under `msc4500:lthash16:blake3:v1`. Every backend below
//! changes the lattice coordinates and therefore every state digest, so each
//! candidate carries its own domain-separation tag and exists only to answer
//! "what would this cost?" (the question asked in `session-ses_f06b.md`).
//! Neither candidate should ever replace a shipped path without a new version
//! in its tag: they are throughput experiments, not federation options.
//!
//! # Constructions
//!
//! All backends take the same framed element bytes the shipped stacks hash —
//! `dst || u16le(len(type)) || type || u16le(len(state_key)) || state_key ||
//! event_id` — and produce 2048 bytes (1024 little-endian `u16` lanes):
//!
//! - **sha512-ctr** (`msc4500:lthash16:sha512-ctr:v1`): `prk = SHA-512(frame)`,
//!   then 32 blocks `SHA-512(prk || u32be(i))` for `i = 0..31` (HKDF-Expand
//!   shape, HMAC elided). That is 33 SHA-512 evaluations for a short element,
//!   all scalar: SHA-NI on x86 accelerates SHA-256 only, so this is the
//!   hand-rolled compression function above, nothing else.
//! - **aes-ctr-ni / aes-ctr-portable** (`msc4500:lthash16:aes-ctr:v1`):
//!   `key = BLAKE3-256(frame)` used directly as the AES-256 key, then 128
//!   blocks `AES-256(u128be(i))` for `i = 0..127`. There is no nonce: the key
//!   derives from the element, so a counter restarting at zero for every
//!   expansion never repeats a key/counter pair. Both variants share the
//!   BLAKE3 key derivation *and* the scalar key schedule, so the only thing
//!   that differs between them is how blocks are encrypted — which is the
//!   point of timing them as two separate metrics.
//!
//! # Cache-timing caveat (portable path)
//!
//! `aes-ctr-portable` is what a build without AES-NI (wasm32, non-x86 targets)
//! would run: 4 KiB of T-tables with 16 secret-dependent lookups per round.
//! That is the classic AES cache-timing / cache-amplification surface
//! (Bernstein 2005; Osvik-Shamir-Tromer 2005), and it is at its worst on wasm,
//! where there is neither AES-NI nor any way to pin down cache behaviour. A
//! wall-clock throughput bench cannot observe the side channel at all, so read
//! `aes-ctr-portable` numbers as "cost of the portable path" and never as "the
//! portable path is safe".
//!
//! Every candidate is proved correct before it is timed (NIST/FIPS vectors,
//! `sha2` cross-checks, AES-NI versus portable differential) by
//! [`check`].
//!
//! Run with: `cargo bench --manifest-path benches/Cargo.toml -- lthash_backends`

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

/// Seed length: 1024 little-endian 16-bit lanes, as everywhere else in LtHash.
pub const SEED_BYTES: usize = 2048;

/// Domain separation for the hand-rolled SHA-512 CTR candidate.
pub const DST_SHA512_CTR: &[u8] = b"msc4500:lthash16:sha512-ctr:v1";

/// Domain separation for the AES-256-CTR candidates (both AES paths).
pub const DST_AES_CTR: &[u8] = b"msc4500:lthash16:aes-ctr:v1";

/// True when this CPU can execute the AES-NI path. Always false on targets
/// that are not x86, which is exactly the population that would run the
/// portable fallback (wasm32 among them).
pub fn aes_ni_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// SHA-512 CTR expansion: `SHA-512(prk || u32be(i))` blocks over
/// `prk = SHA-512(frame)`.
pub fn expand_sha512_ctr(frame: &[u8], out: &mut [u8]) {
    let prk = sha512::hash(frame);
    sha512::ctr_expand(&prk, out);
}

/// AES-256-CTR expansion keyed by `BLAKE3-256(frame)`. `ni` asks for the
/// hardware block cipher; it is ignored (and the metric omitted by the bench)
/// when [`aes_ni_available`] is false.
pub fn expand_aes_ctr(frame: &[u8], out: &mut [u8], ni: bool) {
    let key = blake3::hash(frame);
    aes::ctr_expand_with_key(key.as_bytes(), out, ni);
}

/// Proves every candidate is the algorithm it claims to be before any of them
/// is timed. Panics on the first mismatch.
pub fn check() {
    sha512::check();
    aes::check();

    let frame = b"msc4500:lthash16:sha512-ctr:v1-example-frame";
    let mut a = [0u8; SEED_BYTES];
    let mut b = [0u8; SEED_BYTES];
    expand_sha512_ctr(frame, &mut a);
    expand_sha512_ctr(frame, &mut b);
    assert_eq!(a, b, "sha512-ctr expansion is not deterministic");
    expand_aes_ctr(frame, &mut a, false);
    expand_aes_ctr(frame, &mut b, false);
    assert_eq!(a, b, "aes-ctr expansion is not deterministic");
    expand_aes_ctr(frame, &mut a, true);
    let mut portable = [0u8; SEED_BYTES];
    expand_aes_ctr(frame, &mut portable, false);
    if aes_ni_available() {
        assert_eq!(
            a, portable,
            "AES-NI and portable keystreams diverge on a real frame"
        );
    }
    println!("  candidate expansion determinism: ok");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Hand-rolled SHA-512: the compression function, the single-shot [`hash`],
/// and the counter-mode squeeze of [`ctr_expand`].
pub mod sha512 {
    use super::hex;

    /// Fractional parts of the cube roots of the first 80 primes (FIPS 180-4,
    /// 4.2.3), checked against the published SHA-512 vectors in [`check`].
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    /// Fractional parts of the square roots of the first 8 primes.
    const H0: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    /// SHA-512 of an arbitrary-length message.
    pub fn hash(msg: &[u8]) -> [u8; 64] {
        let mut state = H0;
        let mut chunks = msg.chunks_exact(128);
        for block in chunks.by_ref() {
            let mut padded = [0u8; 128];
            padded.copy_from_slice(block);
            compress(&mut state, &padded);
        }

        // One- or two-block padding tail: remainder, 0x80, zeros, 128-bit
        // big-endian bit length.
        let rem = chunks.remainder();
        let mut tail = [0u8; 256];
        tail[..rem.len()].copy_from_slice(rem);
        tail[rem.len()] = 0x80;
        let tail_len = if rem.len() < 112 { 128 } else { 256 };
        let bit_len = (msg.len() as u128).wrapping_mul(8);
        tail[tail_len - 16..tail_len].copy_from_slice(&bit_len.to_be_bytes());
        for block in tail[..tail_len].chunks_exact(128) {
            let mut padded = [0u8; 128];
            padded.copy_from_slice(block);
            compress(&mut state, &padded);
        }
        pack(&state)
    }

    /// Squeezes `out` (a multiple of 64 bytes) from `prk`: block `i` is
    /// `SHA-512(prk || u32be(i))`.
    pub fn ctr_expand(prk: &[u8; 64], out: &mut [u8]) {
        debug_assert_eq!(out.len() % 64, 0);
        for (i, chunk) in out.chunks_exact_mut(64).enumerate() {
            let mut block = [0u8; 128];
            block[..64].copy_from_slice(prk);
            block[64..68].copy_from_slice(&(i as u32).to_be_bytes());
            block[68] = 0x80;
            // Message is 68 bytes = 544 bits; length field is the last 16.
            block[112..128].copy_from_slice(&544u128.to_be_bytes());
            let mut state = H0;
            compress(&mut state, &block);
            chunk.copy_from_slice(&pack(&state));
        }
    }

    /// One SHA-512 compression over a full 128-byte block.
    fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for (i, word) in w[..16].iter_mut().enumerate() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *word = u64::from_be_bytes(bytes);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
        let (mut e, mut f, mut g, mut h) = (state[4], state[5], state[6], state[7]);
        for i in 0..80 {
            let sum1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(sum1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let sum0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = sum0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    fn pack(state: &[u64; 8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (chunk, word) in out.chunks_exact_mut(8).zip(state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Published SHA-512 vectors plus a differential check against `sha2`,
    /// which covers every padding boundary worth worrying about.
    pub fn check() {
        use sha2::Digest as _;

        const EMPTY: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        const ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        assert_eq!(hex(&hash(b"")), EMPTY, "SHA-512 empty vector");
        assert_eq!(hex(&hash(b"abc")), ABC, "SHA-512 \"abc\" vector");

        for len in [
            0usize, 1, 55, 56, 63, 64, 65, 111, 112, 113, 127, 128, 129, 255, 256, 257, 1000,
        ] {
            let msg: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
                .collect();
            let mine = hash(&msg);
            let mut sha2_hasher = <sha2::Sha512 as sha2::Digest>::new();
            sha2_hasher.update(&msg);
            let theirs = sha2_hasher.finalize();
            assert_eq!(
                mine.as_slice(),
                theirs.as_slice(),
                "sha512 mismatch at len {len}"
            );
        }
        println!("  hand-rolled SHA-512 (NIST vectors + sha2 differential): ok");
    }
}

/// AES-256: derived S-box/T-tables, the scalar key schedule shared by both
/// paths, a portable T-table encryptor, and the AES-NI encryptor.
pub mod aes {
    use super::{aes_ni_available, hex};

    const SBOX: [u8; 256] = build_sbox();
    const TE: [[u32; 256]; 4] = build_te();

    /// AES-256 round keys: 15 x 4 words, big-endian (FIPS 197 order).
    pub struct RoundKeys([u32; 60]);

    /// Expands a 32-byte AES-256 key into the full round-key schedule.
    pub fn expand_key(key: &[u8; 32]) -> RoundKeys {
        let mut w = [0u32; 60];
        for (i, word) in w[..8].iter_mut().enumerate() {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&key[i * 4..i * 4 + 4]);
            *word = u32::from_be_bytes(bytes);
        }
        let mut rcon = 1u32;
        for i in 8..60 {
            let mut temp = w[i - 1];
            if i % 8 == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ (rcon << 24);
                rcon = gf_mul(rcon as u8, 2) as u32;
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            w[i] = w[i - 8] ^ temp;
        }
        RoundKeys(w)
    }

    /// Portable AES-256 block encryption: T-table rounds (four 1 KiB tables).
    fn encrypt_block(rk: &RoundKeys, block: &[u8; 16]) -> [u8; 16] {
        let mut s = [0u32; 4];
        for (i, word) in s.iter_mut().enumerate() {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&block[i * 4..i * 4 + 4]);
            *word = u32::from_be_bytes(bytes);
        }
        for (word, key) in s.iter_mut().zip(&rk.0[..4]) {
            *word ^= key;
        }

        // Rounds 1..=13: SubBytes + ShiftRows + MixColumns + AddRoundKey,
        // with the row shift folded into the table indices.
        for round in 1..14usize {
            let [a0, a1, a2, a3] = s;
            let k = &rk.0[4 * round..];
            s[0] = te(0, a0 >> 24) ^ te(1, a1 >> 16) ^ te(2, a2 >> 8) ^ te(3, a3) ^ k[0];
            s[1] = te(0, a1 >> 24) ^ te(1, a2 >> 16) ^ te(2, a3 >> 8) ^ te(3, a0) ^ k[1];
            s[2] = te(0, a2 >> 24) ^ te(1, a3 >> 16) ^ te(2, a0 >> 8) ^ te(3, a1) ^ k[2];
            s[3] = te(0, a3 >> 24) ^ te(1, a0 >> 16) ^ te(2, a1 >> 8) ^ te(3, a2) ^ k[3];
        }

        // Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns).
        let [a0, a1, a2, a3] = s;
        let words = [
            sub(a0, 24) << 24 | sub(a1, 16) << 16 | sub(a2, 8) << 8 | sub(a3, 0),
            sub(a1, 24) << 24 | sub(a2, 16) << 16 | sub(a3, 8) << 8 | sub(a0, 0),
            sub(a2, 24) << 24 | sub(a3, 16) << 16 | sub(a0, 8) << 8 | sub(a1, 0),
            sub(a3, 24) << 24 | sub(a0, 16) << 16 | sub(a1, 8) << 8 | sub(a2, 0),
        ];
        let mut out = [0u8; 16];
        for (i, word) in words.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&(word ^ rk.0[56 + i]).to_be_bytes());
        }
        out
    }

    /// Counter-mode squeeze with an explicit AES-256 key. `ni` selects the
    /// hardware encryptor (falling back to portable if the CPU lacks AES-NI).
    pub fn ctr_expand_with_key(key: &[u8; 32], out: &mut [u8], ni: bool) {
        let rk = expand_key(key);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if ni && aes_ni_available() {
                let rk128 = ni::RoundKeys128::new(&rk);
                // SAFETY: `aes_ni_available()` confirmed the AES-NI feature.
                unsafe { ni::ctr_expand(&rk128, out) };
                return;
            }
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let _ = ni;
        for (i, chunk) in out.chunks_exact_mut(16).enumerate() {
            chunk.copy_from_slice(&encrypt_block(&rk, &(i as u128).to_be_bytes()));
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn encrypt_block_ni(rk: &RoundKeys, block: &[u8; 16]) -> [u8; 16] {
        let rk128 = ni::RoundKeys128::new(rk);
        // SAFETY: every caller of this helper has checked `aes_ni_available()`.
        unsafe { ni::encrypt(&rk128, block) }
    }

    fn te(table: usize, byte: u32) -> u32 {
        TE[table][(byte & 0xff) as usize]
    }

    fn sub(word: u32, shift: u32) -> u32 {
        SBOX[((word >> shift) & 0xff) as usize] as u32
    }

    fn sub_word(word: u32) -> u32 {
        let b = word.to_be_bytes();
        u32::from_be_bytes([
            SBOX[b[0] as usize],
            SBOX[b[1] as usize],
            SBOX[b[2] as usize],
            SBOX[b[3] as usize],
        ])
    }

    const fn gf_mul(a: u8, b: u8) -> u8 {
        let mut acc = 0u8;
        let mut x = a;
        let mut y = b;
        while y != 0 {
            if y & 1 != 0 {
                acc ^= x;
            }
            let high = x & 0x80;
            x <<= 1;
            if high != 0 {
                x ^= 0x1b;
            }
            y >>= 1;
        }
        acc
    }

    const fn gf_inv(x: u8) -> u8 {
        if x == 0 {
            return 0;
        }
        // x^(2^8 - 2) = x^-1 in GF(2^8); square-and-multiply, straight line.
        let mut result = 1u8;
        let mut base = x;
        let mut exp = 254u8;
        while exp != 0 {
            if exp & 1 == 1 {
                result = gf_mul(result, base);
            }
            base = gf_mul(base, base);
            exp >>= 1;
        }
        result
    }

    const fn rotl8(v: u8, n: u32) -> u8 {
        v.rotate_left(n)
    }

    const fn build_sbox() -> [u8; 256] {
        let mut sbox = [0u8; 256];
        let mut i = 0usize;
        while i < 256 {
            let inv = gf_inv(i as u8);
            sbox[i] = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63;
            i += 1;
        }
        sbox
    }

    /// The four MixColumns tables: `TE[t][x]` is byte `S[x]` scaled by the
    /// `t`-th column of the MixColumns matrix.
    const fn build_te() -> [[u32; 256]; 4] {
        let mut te = [[0u32; 256]; 4];
        let mut x = 0usize;
        while x < 256 {
            let s = SBOX[x];
            let s2 = gf_mul(s, 2);
            let s3 = gf_mul(s, 3);
            te[0][x] = (s2 as u32) << 24 | (s as u32) << 16 | (s as u32) << 8 | s3 as u32;
            te[1][x] = (s3 as u32) << 24 | (s2 as u32) << 16 | (s as u32) << 8 | s as u32;
            te[2][x] = (s as u32) << 24 | (s3 as u32) << 16 | (s2 as u32) << 8 | s as u32;
            te[3][x] = (s as u32) << 24 | (s as u32) << 16 | (s3 as u32) << 8 | s2 as u32;
            x += 1;
        }
        te
    }

    /// AES-NI block cipher: round keys as `__m128i`, `aesenc` rounds, runtime
    /// feature detection at every entry point.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub(super) mod ni {
        #[cfg(target_arch = "x86")]
        use std::arch::x86 as imp;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64 as imp;

        use super::RoundKeys;

        pub(super) struct RoundKeys128([imp::__m128i; 15]);

        impl RoundKeys128 {
            pub(super) fn new(rk: &RoundKeys) -> Self {
                // SAFETY: zeroing and loading plain memory needs no feature.
                let mut out = [unsafe { imp::_mm_setzero_si128() }; 15];
                for (r, key) in out.iter_mut().enumerate() {
                    let mut bytes = [0u8; 16];
                    for (word, slot) in rk.0[4 * r..4 * r + 4].iter().zip(bytes.chunks_exact_mut(4))
                    {
                        slot.copy_from_slice(&word.to_be_bytes());
                    }
                    *key = unsafe { imp::_mm_loadu_si128(bytes.as_ptr() as *const imp::__m128i) };
                }
                Self(out)
            }
        }

        /// One AES-256 block: xor round key 0, thirteen `aesenc`,
        /// `aesenclast`.
        #[target_feature(enable = "aes")]
        pub(super) unsafe fn encrypt(rk: &RoundKeys128, block: &[u8; 16]) -> [u8; 16] {
            let loaded = imp::_mm_loadu_si128(block.as_ptr() as *const imp::__m128i);
            let a = rounds(&rk.0, loaded);
            let mut out = [0u8; 16];
            imp::_mm_storeu_si128(out.as_mut_ptr() as *mut imp::__m128i, a);
            out
        }

        /// Counter-mode squeeze: block `i` is `AES-256(u128be(i))`.
        #[target_feature(enable = "aes")]
        pub(super) unsafe fn ctr_expand(rk: &RoundKeys128, out: &mut [u8]) {
            for (i, chunk) in out.chunks_exact_mut(16).enumerate() {
                let counter = (i as u128).to_be_bytes();
                let loaded = imp::_mm_loadu_si128(counter.as_ptr() as *const imp::__m128i);
                let a = rounds(&rk.0, loaded);
                imp::_mm_storeu_si128(chunk.as_mut_ptr() as *mut imp::__m128i, a);
            }
        }

        #[target_feature(enable = "aes")]
        unsafe fn rounds(rk: &[imp::__m128i; 15], mut a: imp::__m128i) -> imp::__m128i {
            a = imp::_mm_xor_si128(a, rk[0]);
            for key in &rk[1..14] {
                a = imp::_mm_aesenc_si128(a, *key);
            }
            imp::_mm_aesenclast_si128(a, rk[14])
        }
    }

    /// FIPS 197 vectors plus an AES-NI/portable differential run.
    pub fn check() {
        assert_eq!(SBOX[0x00], 0x63, "S-box anchor S(0)");
        assert_eq!(SBOX[0x01], 0x7c, "S-box anchor S(1)");
        assert_eq!(SBOX[0x53], 0xed, "S-box anchor S(0x53)");
        assert_eq!(SBOX[0xff], 0x16, "S-box anchor S(0xff)");

        // FIPS 197 A.1: key 00..1f, plaintext 001122..ff.
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let plaintext: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(0x11));
        let want = "8ea2b7ca516745bfeafc49904b496089";
        let rk = expand_key(&key);
        assert_eq!(
            hex(&encrypt_block(&rk, &plaintext)),
            want,
            "AES-256 FIPS KAT (portable)"
        );

        // AES-256 CTR keystream for counters 0..3 (independently computed).
        let want_ks = "f29000b62a499fd0a9f39a6add2e7780\
                       f05d76ae4ab99fe5a6f69b3148c2363d\
                       0ebcb5deb52c83bd08a8a935182c9199\
                       d24356532881602f809eb383c5ff5d56";
        let mut ks = [0u8; 64];
        ctr_expand_with_key(&key, &mut ks, false);
        assert_eq!(hex(&ks), want_ks, "AES-256 CTR keystream (portable)");
        println!("  AES-256 portable path (S-box, FIPS-197 KAT, CTR vector): ok");

        if aes_ni_available() {
            assert_eq!(
                hex(&encrypt_block_ni(&rk, &plaintext)),
                want,
                "AES-256 FIPS KAT (AES-NI)"
            );
            let mut ni_ks = [0u8; 64];
            ctr_expand_with_key(&key, &mut ni_ks, true);
            assert_eq!(hex(&ni_ks), want_ks, "AES-256 CTR keystream (AES-NI)");

            // Differential run over deterministic pseudo-random blocks.
            let mut state = 0x9e37_79b9u32;
            for _ in 0..256 {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let mut block = [0u8; 16];
                for byte in &mut block {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    *byte = (state >> 24) as u8;
                }
                assert_eq!(
                    encrypt_block_ni(&rk, &block),
                    encrypt_block(&rk, &block),
                    "AES-NI diverged from the portable path"
                );
            }
            println!("  AES-256 AES-NI path (FIPS KAT, CTR vector, 256-block differential): ok");
        } else {
            println!("  AES-NI: unavailable on this CPU (hardware path not exercised)");
        }
    }
}

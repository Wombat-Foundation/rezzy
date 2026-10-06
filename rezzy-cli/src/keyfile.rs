//! Passphrase-encrypted signing-key files.
//!
//! Layout: `MAGIC(8) | m_cost KiB (u32 BE) | t_cost (u32 BE) | lanes (u32 BE) |
//! salt(16) | nonce(24) | ciphertext+tag`. The key is derived with Argon2id and
//! the payload sealed with XChaCha20-Poly1305. Everything before the
//! ciphertext is bound as associated data, so tampering with the KDF
//! parameters fails authentication.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};

const MAGIC: &[u8; 8] = b"REZKEY\x00\x01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + 12 + SALT_LEN + NONCE_LEN;
/// Upper bounds on header-declared KDF cost, so a hostile file cannot force
/// a huge allocation before authentication.
const MAX_M_COST_KIB: u32 = 64 * 1024;
const MAX_T_COST: u32 = 3;
const MAX_LANES: u32 = 1;

const DEFAULT_M_COST_KIB: u32 = 64 * 1024;
const DEFAULT_T_COST: u32 = 3;
const DEFAULT_LANES: u32 = 1;

fn derive(passphrase: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32], String> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| format!("invalid KDF params: {e}"))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

fn seal_with(
    plaintext: &[u8],
    passphrase: &[u8],
    (m, t, p): (u32, u32, u32),
) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| format!("rng failure: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| format!("rng failure: {e}"))?;

    let mut out = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(plaintext.len())
            .saturating_add(16),
    );
    out.extend_from_slice(MAGIC);
    for v in [m, t, p] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);

    let mut key = derive(passphrase, &salt, m, t, p)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.fill(0);
    let ct = cipher
        .encrypt(
            &XNonce::try_from(&nonce[..]).map_err(|_| "bad nonce".to_owned())?,
            Payload {
                msg: plaintext,
                aad: &out,
            },
        )
        .map_err(|_| "encryption failed".to_owned())?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Encrypt `plaintext` under `passphrase` with default (interactive-strength) KDF costs.
///
/// # Errors
/// Returns an error if the RNG, KDF, or cipher fails.
pub fn seal(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
    seal_with(
        plaintext,
        passphrase,
        (DEFAULT_M_COST_KIB, DEFAULT_T_COST, DEFAULT_LANES),
    )
}

/// Decrypt a file produced by [`seal`].
///
/// # Errors
/// Returns an error for malformed files, out-of-range KDF parameters, or a
/// wrong passphrase / corrupted ciphertext (indistinguishable by design).
pub fn open(file: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
    if file.len() < HEADER_LEN + 16 || &file[..MAGIC.len()] != MAGIC {
        return Err("not a rezzy encrypted key file".to_owned());
    }
    let params = file
        .get(8..20)
        .ok_or_else(|| "truncated key file".to_owned())?;
    let mut words = params
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
    let (m, t, p) = (
        words.next().unwrap_or(0),
        words.next().unwrap_or(0),
        words.next().unwrap_or(0),
    );
    if m > MAX_M_COST_KIB || t == 0 || t > MAX_T_COST || p == 0 || p > MAX_LANES {
        return Err("encrypted key file has unsupported KDF parameters".to_owned());
    }
    let salt = &file[20..20_usize.saturating_add(SALT_LEN)];
    let nonce = &file[20_usize.saturating_add(SALT_LEN)..HEADER_LEN];
    let mut key = derive(passphrase, salt, m, t, p)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.fill(0);
    cipher
        .decrypt(
            &XNonce::try_from(nonce).map_err(|_| "bad nonce".to_owned())?,
            Payload {
                msg: &file[HEADER_LEN..],
                aad: &file[..HEADER_LEN],
            },
        )
        .map_err(|_| "wrong passphrase or corrupted key file".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: (u32, u32, u32) = (8, 1, 1);

    #[test]
    fn roundtrip() {
        let f = seal_with(b"ed25519:a secret", b"pw", FAST).unwrap();
        assert_eq!(open(&f, b"pw").unwrap(), b"ed25519:a secret");
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let f = seal_with(b"x", b"pw", FAST).unwrap();
        assert!(open(&f, b"nope").is_err());
    }

    #[test]
    fn tampering_rejected() {
        let f = seal_with(b"payload", b"pw", FAST).unwrap();
        for i in [9, 15, 25, HEADER_LEN, f.len() - 1] {
            let mut g = f.clone();
            g[i] ^= 1;
            assert!(open(&g, b"pw").is_err(), "byte {i}");
        }
    }

    #[test]
    fn garbage_and_hostile_params_rejected() {
        assert!(open(b"short", b"pw").is_err());
        let mut f = seal_with(b"x", b"pw", FAST).unwrap();
        f[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(open(&f, b"pw").unwrap_err().contains("unsupported"));
    }

    #[test]
    fn salts_differ() {
        let a = seal_with(b"x", b"pw", FAST).unwrap();
        let b = seal_with(b"x", b"pw", FAST).unwrap();
        assert_ne!(a, b);
    }
}

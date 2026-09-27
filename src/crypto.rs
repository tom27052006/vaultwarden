//
// PBKDF2 derivation
//
use std::{num::NonZeroU32, sync::OnceLock};

use data_encoding::{BASE64URL_NOPAD, Encoding, HEXLOWER};
use ring::{aead, digest, hkdf, hmac, pbkdf2};

use crate::Error;

const DIGEST_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const OUTPUT_LEN: usize = digest::SHA256_OUTPUT_LEN;

const DATABASE_FIELD_PROTECTED_PREFIX: &str = "P|1|";
const DATABASE_FIELD_KEY_LEN: usize = 32;
const DATABASE_FIELD_KDF_SALT: &[u8] = b"vaultwarden/database-field-protection/v1";
const DATABASE_FIELD_KDF_INFO: &[u8] = b"OrganizationInviteLink.Code";
static DATABASE_FIELD_CIPHER: OnceLock<DatabaseFieldCipher> = OnceLock::new();

struct DatabaseFieldKeyLen;

impl hkdf::KeyType for DatabaseFieldKeyLen {
    fn len(&self) -> usize {
        DATABASE_FIELD_KEY_LEN
    }
}

struct DatabaseFieldCipher(aead::LessSafeKey);

impl DatabaseFieldCipher {
    fn from_installation_secret(secret: &[u8]) -> Result<Self, Error> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, DATABASE_FIELD_KDF_SALT);
        let prk = salt.extract(secret);
        let okm = prk
            .expand(&[DATABASE_FIELD_KDF_INFO], DatabaseFieldKeyLen)
            .map_err(|_| Error::new_msg("Failed to derive the database field protection key"))?;
        let mut key = [0_u8; DATABASE_FIELD_KEY_LEN];
        okm.fill(&mut key).map_err(|_| Error::new_msg("Failed to derive the database field protection key"))?;
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| Error::new_msg("Failed to initialize database field protection"))?;
        Ok(Self(aead::LessSafeKey::new(key)))
    }

    fn protect(&self, plaintext: &str, associated_data: &[u8]) -> Result<String, Error> {
        let nonce_bytes = get_random_bytes::<{ aead::NONCE_LEN }>();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut protected = plaintext.as_bytes().to_vec();
        self.0
            .seal_in_place_append_tag(nonce, aead::Aad::from(associated_data), &mut protected)
            .map_err(|_| Error::new_msg("Failed to protect database field"))?;

        let mut envelope = Vec::with_capacity(aead::NONCE_LEN + protected.len());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&protected);
        Ok(format!("{DATABASE_FIELD_PROTECTED_PREFIX}{}", BASE64URL_NOPAD.encode(&envelope)))
    }

    fn unprotect(&self, protected: &str, associated_data: &[u8]) -> Result<String, Error> {
        let encoded = protected
            .strip_prefix(DATABASE_FIELD_PROTECTED_PREFIX)
            .ok_or_else(|| Error::new_msg("Unsupported database field protection format"))?;
        let envelope = BASE64URL_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| Error::new_msg("Invalid protected database field encoding"))?;
        if envelope.len() < aead::NONCE_LEN + aead::AES_256_GCM.tag_len() {
            return Err(Error::new_msg("Invalid protected database field length"));
        }

        let (nonce_bytes, ciphertext) = envelope.split_at(aead::NONCE_LEN);
        let nonce_bytes: [u8; aead::NONCE_LEN] =
            nonce_bytes.try_into().map_err(|_| Error::new_msg("Invalid protected database field nonce"))?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut ciphertext = ciphertext.to_vec();
        let plaintext = self
            .0
            .open_in_place(nonce, aead::Aad::from(associated_data), &mut ciphertext)
            .map_err(|_| Error::new_msg("Database field authentication failed"))?;
        String::from_utf8(plaintext.to_vec()).map_err(|_| Error::new_msg("Protected database field is not UTF-8"))
    }
}

/// Derives the database field protection key from Vaultwarden's persistent installation RSA key.
/// HKDF domain separation ensures the derived AEAD key is independent from the key's JWT use.
pub fn initialize_database_field_key(installation_secret: &[u8]) -> Result<(), Error> {
    let cipher = DatabaseFieldCipher::from_installation_secret(installation_secret)?;
    DATABASE_FIELD_CIPHER
        .set(cipher)
        .map_err(|_| Error::new_msg("Database field protection must only be initialized once"))
}

pub fn is_protected_database_field(value: &str) -> bool {
    value.starts_with("P|")
}

pub fn protect_database_field(plaintext: &str, associated_data: &[u8]) -> Result<String, Error> {
    DATABASE_FIELD_CIPHER.wait().protect(plaintext, associated_data)
}

pub fn unprotect_database_field(protected: &str, associated_data: &[u8]) -> Result<String, Error> {
    DATABASE_FIELD_CIPHER.wait().unprotect(protected, associated_data)
}

pub fn hash_password(secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = vec![0u8; OUTPUT_LEN]; // Initialize array with zeros

    let iterations = NonZeroU32::new(iterations).expect("Iterations can't be zero");
    pbkdf2::derive(DIGEST_ALG, iterations, salt, secret, &mut out);

    out
}

pub fn verify_password_hash(secret: &[u8], salt: &[u8], previous: &[u8], iterations: u32) -> bool {
    let iterations = NonZeroU32::new(iterations).expect("Iterations can't be zero");
    pbkdf2::verify(DIGEST_ALG, iterations, salt, secret, previous).is_ok()
}

//
// HMAC
//
pub fn hmac_sign(key: &str, data: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_bytes());
    let signature = hmac::sign(&key, data.as_bytes());

    HEXLOWER.encode(signature.as_ref())
}

//
// Random values
//

/// Return an array holding `N` random bytes.
pub fn get_random_bytes<const N: usize>() -> [u8; N] {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut array = [0; N];
    SystemRandom::new().fill(&mut array).expect("Error generating random values");

    array
}

/// Encode random bytes using the provided function.
pub fn encode_random_bytes<const N: usize>(e: &Encoding) -> String {
    e.encode(&get_random_bytes::<N>())
}

/// Generates a random string over a specified alphabet.
pub fn get_random_string(alphabet: &[u8], num_chars: usize) -> String {
    // Ref: https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
    use rand::RngExt;
    let mut rng = rand::rng();

    (0..num_chars)
        .map(|_| {
            let i = rng.random_range(0..alphabet.len());
            char::from(alphabet[i])
        })
        .collect()
}

/// Generates a random numeric string.
pub fn get_random_string_numeric(num_chars: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789";
    get_random_string(ALPHABET, num_chars)
}

/// Generates a random alphanumeric string.
pub fn get_random_string_alphanum(num_chars: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                              abcdefghijklmnopqrstuvwxyz\
                              0123456789";
    get_random_string(ALPHABET, num_chars)
}

pub fn generate_id<const N: usize>() -> String {
    encode_random_bytes::<N>(&HEXLOWER)
}

pub fn generate_send_file_id() -> String {
    // Send File IDs are globally scoped, so make them longer to avoid collisions.
    generate_id::<32>() // 256 bits
}

use crate::db::models::AttachmentId;
pub fn generate_attachment_id() -> AttachmentId {
    // Attachment IDs are scoped to a cipher, so they can be smaller.
    AttachmentId(generate_id::<10>()) // 80 bits
}

/// Generates a numeric token for email-based verifications.
pub fn generate_email_token(token_size: u8) -> String {
    get_random_string_numeric(token_size as usize)
}

/// Generates a personal API key.
/// Upstream uses 30 chars, which is ~178 bits of entropy.
pub fn generate_api_key() -> String {
    get_random_string_alphanum(30)
}

//
// Constant time compare
//
pub fn ct_eq<T: AsRef<[u8]>, U: AsRef<[u8]>>(a: T, b: U) -> bool {
    use subtle::ConstantTimeEq;
    a.as_ref().ct_eq(b.as_ref()).into()
}

//
// SHA256
//
pub fn sha256_hex(data: &[u8]) -> String {
    HEXLOWER.encode(digest::digest(&digest::SHA256, data).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_field_protection_survives_key_reinitialization() {
        let before_restart = DatabaseFieldCipher::from_installation_secret(b"persistent installation key").unwrap();
        let protected = before_restart.protect("26ea8c3b-9f70-41a1-a1d7-d4c9e4c3d07f", b"org-1").unwrap();
        assert!(protected.starts_with(DATABASE_FIELD_PROTECTED_PREFIX));
        assert!(!protected.contains("26ea8c3b-9f70-41a1-a1d7-d4c9e4c3d07f"));

        let after_restart = DatabaseFieldCipher::from_installation_secret(b"persistent installation key").unwrap();
        assert_eq!(after_restart.unprotect(&protected, b"org-1").unwrap(), "26ea8c3b-9f70-41a1-a1d7-d4c9e4c3d07f");
    }

    #[test]
    fn database_field_protection_authenticates_ciphertext_and_context() {
        let cipher = DatabaseFieldCipher::from_installation_secret(b"persistent installation key").unwrap();
        let protected = cipher.protect("secret", b"org-1").unwrap();
        assert!(cipher.unprotect(&protected, b"org-2").is_err());

        let mut tampered = protected.into_bytes();
        let position = tampered.len() / 2;
        tampered[position] = if tampered[position] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered = String::from_utf8(tampered).unwrap();
        assert!(cipher.unprotect(&tampered, b"org-1").is_err());
    }
}

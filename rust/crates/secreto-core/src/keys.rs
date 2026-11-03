//! Key types and their Bech32 encodings (`spec/registry.md`, *Bech32 HRPs*).

use crate::bech32;
use crate::error::{Error, Result};
use crate::kem;
use crate::sign::{SignerPublicKey, SigningKey, PK_LEN, SK_LEN};
use zeroize::Zeroizing;

/// HRP of recipients (public encapsulation keys).
pub const HRP_RECIPIENT: &str = "secreto";
/// HRP of identities (secret seeds).
pub const HRP_IDENTITY: &str = "SECRETO-SECRET-KEY-";
/// HRP of signing secret keys.
pub const HRP_SIGNING_KEY: &str = "SECRETO-SIGNING-KEY-";
/// HRP of signer public keys.
pub const HRP_SIGNER_PUBLIC: &str = "secretosig";

/// A decryption identity: the 32-byte MLKEM1024-P384 seed.
pub struct Identity {
    seed: Zeroizing<[u8; kem::SEED_LEN]>,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Identity(..)")
    }
}

impl Identity {
    /// Generate a fresh identity.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            seed: kem::generate_seed()?,
        })
    }

    /// Construct from a 32-byte seed.
    pub fn from_seed(seed: [u8; kem::SEED_LEN]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    /// The 32-byte seed.
    pub fn seed(&self) -> &[u8; kem::SEED_LEN] {
        &self.seed
    }

    /// Bech32 encoding (`SECRETO-SECRET-KEY-1...`).
    pub fn to_bech32(&self) -> Zeroizing<String> {
        Zeroizing::new(
            bech32::encode(HRP_IDENTITY, &*self.seed).expect("fixed-size data always encodes"),
        )
    }

    /// Parse a Bech32 identity.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let data = Zeroizing::new(bech32::decode_exact(s, HRP_IDENTITY, kem::SEED_LEN)?);
        let mut seed = [0u8; kem::SEED_LEN];
        seed.copy_from_slice(&data);
        Ok(Self::from_seed(seed))
    }

    /// The corresponding recipient.
    pub fn recipient(&self) -> Result<Recipient> {
        let (_, ek) = kem::derive_key_pair(&self.seed)?;
        Recipient::from_bytes(&ek)
    }
}

/// An encryption recipient: the 1665-byte MLKEM1024-P384 encapsulation key.
#[derive(Clone, PartialEq, Eq)]
pub struct Recipient {
    ek: Box<[u8; kem::EK_LEN]>,
}

impl core::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Recipient({}..)",
            self.to_bech32().chars().take(16).collect::<String>()
        )
    }
}

impl Recipient {
    /// Construct from the 1665-byte encapsulation key, validating it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        kem::validate_ek(bytes)?;
        let mut ek = Box::new([0u8; kem::EK_LEN]);
        ek.copy_from_slice(bytes);
        Ok(Self { ek })
    }

    /// The encapsulation key bytes.
    pub fn as_bytes(&self) -> &[u8; kem::EK_LEN] {
        &self.ek
    }

    /// Bech32 encoding (`secreto1...`).
    pub fn to_bech32(&self) -> String {
        bech32::encode(HRP_RECIPIENT, &self.ek[..]).expect("fixed-size data always encodes")
    }

    /// Parse a Bech32 recipient.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let data = bech32::decode_exact(s, HRP_RECIPIENT, kem::EK_LEN)?;
        Self::from_bytes(&data)
    }
}

impl SigningKey {
    /// Bech32 encoding (`SECRETO-SIGNING-KEY-1...`).
    pub fn to_bech32(&self) -> Zeroizing<String> {
        Zeroizing::new(
            bech32::encode(HRP_SIGNING_KEY, self.as_bytes())
                .expect("fixed-size data always encodes"),
        )
    }

    /// Parse a Bech32 signing key.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let data = Zeroizing::new(bech32::decode_exact(s, HRP_SIGNING_KEY, SK_LEN)?);
        Self::from_bytes(&data)
    }
}

impl SignerPublicKey {
    /// Bech32 encoding (`secretosig1...`).
    pub fn to_bech32(&self) -> String {
        bech32::encode(HRP_SIGNER_PUBLIC, self.as_bytes()).expect("fixed-size data always encodes")
    }

    /// Parse a Bech32 signer public key.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let data = bech32::decode_exact(s, HRP_SIGNER_PUBLIC, PK_LEN)?;
        Self::from_bytes(&data)
    }
}

/// Non-empty, non-comment lines of a key / recipient file (`#` starts a
/// comment line; trailing CR is tolerated).
fn key_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// Parse a recipients file: one Bech32 recipient per line, `#` comments.
pub fn parse_recipients(text: &str) -> Result<Vec<Recipient>> {
    let v: Result<Vec<_>> = key_lines(text).map(Recipient::from_bech32).collect();
    let v = v?;
    if v.is_empty() {
        return Err(Error::InvalidKey("no recipients found"));
    }
    Ok(v)
}

/// Parse an identity file: one or more Bech32 identities, `#` comments.
pub fn parse_identities(text: &str) -> Result<Vec<Identity>> {
    let v: Result<Vec<_>> = key_lines(text).map(Identity::from_bech32).collect();
    let v = v?;
    if v.is_empty() {
        return Err(Error::InvalidKey("no identities found"));
    }
    Ok(v)
}

/// Parse a signing key file: exactly one Bech32 signing key.
pub fn parse_signing_key(text: &str) -> Result<SigningKey> {
    let mut it = key_lines(text);
    let first = it.next().ok_or(Error::InvalidKey("no signing key found"))?;
    if it.next().is_some() {
        return Err(Error::InvalidKey("multiple signing keys in file"));
    }
    SigningKey::from_bech32(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip() {
        let id = Identity::from_seed([1u8; 32]);
        let s = id.to_bech32();
        assert!(s.starts_with("SECRETO-SECRET-KEY-1"));
        assert_eq!(s.as_str(), s.to_ascii_uppercase());
        let id2 = Identity::from_bech32(&s).unwrap();
        assert_eq!(id2.seed(), id.seed());
        // lower-case / wrong HRP / wrong length rejected
        assert!(Identity::from_bech32(&s.to_ascii_lowercase()).is_err());
        assert!(Identity::from_bech32(&bech32::encode("secreto", &[0u8; 32]).unwrap()).is_err());
        assert!(Identity::from_bech32(&bech32::encode(HRP_IDENTITY, &[0u8; 31]).unwrap()).is_err());
        // Debug is redacted
        assert!(!format!("{id:?}").contains("01"));
    }

    #[test]
    fn recipient_roundtrip() {
        let id = Identity::from_seed([2u8; 32]);
        let r = id.recipient().unwrap();
        let s = r.to_bech32();
        assert!(s.starts_with("secreto1"));
        assert_eq!(s, s.to_ascii_lowercase());
        assert_eq!(Recipient::from_bech32(&s).unwrap(), r);
        assert!(Recipient::from_bech32(&s.to_ascii_uppercase()).is_err());
        // truncated / invalid key bytes
        let bad = bech32::encode(HRP_RECIPIENT, &r.as_bytes()[..1664]).unwrap();
        assert!(Recipient::from_bech32(&bad).is_err());
        let mut b = r.as_bytes().to_vec();
        b[kem::EK_LEN - 1] ^= 1; // corrupt point
        let bad = bech32::encode(HRP_RECIPIENT, &b).unwrap();
        assert!(Recipient::from_bech32(&bad).is_err());
    }

    #[test]
    fn signing_key_roundtrip() {
        let sk = SigningKey::from_bytes(&[4u8; 64]).unwrap();
        let s = sk.to_bech32();
        assert!(s.starts_with("SECRETO-SIGNING-KEY-1"));
        let sk2 = SigningKey::from_bech32(&s).unwrap();
        assert_eq!(sk2.as_bytes(), sk.as_bytes());
        let pk = sk.public_key();
        let ps = pk.to_bech32();
        assert!(ps.starts_with("secretosig1"));
        assert_eq!(SignerPublicKey::from_bech32(&ps).unwrap(), pk);
        assert!(SignerPublicKey::from_bech32(&s).is_err());
        assert!(SigningKey::from_bech32(&ps).is_err());
    }

    #[test]
    fn file_parsing() {
        let id = Identity::from_seed([3u8; 32]);
        let r = id.recipient().unwrap();
        let text = format!(
            "# comment\n\n{}\r\n  # more\n{}\n",
            r.to_bech32(),
            r.to_bech32()
        );
        assert_eq!(parse_recipients(&text).unwrap().len(), 2);
        assert!(parse_recipients("# nothing\n").is_err());
        assert!(parse_recipients("garbage\n").is_err());

        let text = format!("# created\n{}\n", id.to_bech32().as_str());
        let ids = parse_identities(&text).unwrap();
        assert_eq!(ids.len(), 1);
        assert!(parse_identities("").is_err());
        assert!(parse_identities("secreto1xyz").is_err());

        let sk = SigningKey::from_bytes(&[9u8; 64]).unwrap();
        let text = format!("# sk\n{}\n", sk.to_bech32().as_str());
        assert!(parse_signing_key(&text).is_ok());
        let twice = format!("{text}{text}");
        assert!(parse_signing_key(&twice).is_err());
        assert!(parse_signing_key("").is_err());
    }
}

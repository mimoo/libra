// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

// TODO: rewrite this
//! An implementation of x25519 elliptic curve key pairs required for
//! [Diffie-Hellman key
//! exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
//! in the Libra project.
//!
//! This is an API for [Elliptic Curves for Security - RFC
//! 7748](https://tools.ietf.org/html/rfc7748) and which deals with
//! long-term key generation and handling (`X25519StaticPrivateKey`,
//! `X25519StaticPublicKey`) as well as short-term keys (`X25519EphemeralPrivateKey`,
//! `X25519PublicKey`).
//!
//! The default type for a Diffie-Hellman secret is an ephemeral
//! one, forming a `PrivateKey`-`PublicKey` pair with `X25519Publickey`,
//! and is not serializable, since the use of fresh DH secrets is
//! recommended for various reasons including PFS.
//!
//! We also provide a "static" implementation `X25519StaticPrivateKey`,
//! which supports serialization, forming a `PrivateKey`-`PublicKey` pair
//! with `X25519StaticPublickey`. This later type is precisely a
//! [newtype](https://doc.rust-lang.org/1.5.0/style/features/types/newtype.html)
//! wrapper around `X25519PublicKey`, to which it coerces through `Deref`.
//!
//! # Examples
//!
//! ```
//! use libra_crypto::x25519::*;
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! // Derive an X25519 static key pair from seed using the extract-then-expand HKDF method from RFC 5869.
//! let salt = &b"some salt"[..];
//! // In production, ensure seed has at least 256 bits of entropy.
//! let seed = [5u8; 32]; // seed is denoted as IKM in HKDF RFC 5869.
//! let info = &b"some app info"[..];
//!
//! let (private_key1, public_key1) = X25519StaticPrivateKey::derive_keypair_from_seed(Some(salt), &seed, Some(info));
//! let (private_key2, public_key2) = X25519StaticPrivateKey::derive_keypair_from_seed(Some(salt), &seed, Some(info));
//! assert_eq!(public_key1, public_key2);
//!
//! // Generate a random X25519 ephemeral key pair from an RNG (in this example a StdRng)
//! use libra_crypto::Uniform;
//! let seed = [1u8; 32];
//! let mut rng: StdRng = SeedableRng::from_seed(seed);
//! let private_key = X25519StaticPrivateKey::generate(&mut rng);
//! let public_key: X25519StaticPublicKey = (&private_key).into();
//!
//! // Generate an X25519 key pair from an RNG and a user-provided seed.
//! let salt = &b"some salt"[..];
//! // In production, ensure seed has at least 256 bits of entropy.
//! let seed = [5u8; 32]; // seed is denoted as IKM in HKDF RFC 5869.
//! let info = &b"some app info"[..];
//! let (private_key1, public_key1) = X25519StaticPrivateKey::generate_keypair_hybrid(Some(salt), &seed, Some(info));
//! let (private_key2, public_key2) = X25519StaticPrivateKey::generate_keypair_hybrid(Some(salt), &seed, Some(info));
//! assert_ne!(public_key1, public_key2);
//! ```

use std::convert::{TryFrom, TryInto};

use crate::traits::{self, ValidKey, ValidKeyStringExt};
use libra_crypto_derive::{DeserializeKey, SerializeKey, SilentDebug, SilentDisplay};

#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;

//
// Underlying Implementation
// =========================
//
// We re-export dalek-x25519 library,
// this makes it easier to figure out what flags we want to use to build
//

pub use x25519_dalek::*;

//
// Main types and constants
// ========================
//

/// Size of a X25519 private key
const PRIVATE_KEY_SIZE: usize = 32;
/// Size of a X25519 public key
const PUBLIC_KEY_SIZE: usize = 32;

/// Ideally this type should be used if no cryptography is needed on a X25519 private key
#[derive(DeserializeKey, SilentDisplay, SilentDebug, SerializeKey)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary, Clone, PartialEq))]
pub struct PrivateKeyBytes([u8; PRIVATE_KEY_SIZE]);

/// Ideally this type should be used if no cryptography is needed on a X25519 public key
#[derive(
  Default, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeKey, DeserializeKey,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct PublicKeyBytes([u8; PUBLIC_KEY_SIZE]);

//
// Handy implementations
//

impl PrivateKeyBytes {
  /// converts the wrapper into a vector of bytes
  pub fn to_vec(&self) -> Vec<u8> {
    self.0.to_vec()
  }

  /// obtain the public key part of this private key
  pub fn public_key(&self) -> PublicKeyBytes {
    let private_key: StaticSecret = self.0.into();
    let public_key: PublicKey = (&private_key).into();
    PublicKeyBytes(public_key.as_bytes().to_owned())
  }

  /// only used to test
  // TODO: ideally we would gate this behind a test/testing/fuzzing flag
  pub fn for_test(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> Self {
    Self(StaticSecret::new(rng).to_bytes())
  }
}

impl PublicKeyBytes {
  // TODO: remove this, already implemented for traits
  /// converts the wrapper into a vector of bytes
  pub fn to_bytes(&self) -> Vec<u8> {
    self.0.to_vec()
  }

  /// obtains a slice reference to the underlying bytearray
  pub fn as_slice(&self) -> &[u8] {
    &self.0
  }
}

//
// required for traits...
//

impl std::convert::TryFrom<&[u8]> for PrivateKeyBytes {
  type Error = traits::CryptoMaterialError;

  fn try_from(private_key_bytes: &[u8]) -> Result<Self, Self::Error> {
    let private_key_bytes: [u8; PRIVATE_KEY_SIZE] = private_key_bytes
      .try_into()
      .map_err(|_| traits::CryptoMaterialError::DeserializationError)?;
    Ok(Self(private_key_bytes))
  }
}

impl std::convert::TryFrom<&[u8]> for PublicKeyBytes {
  type Error = traits::CryptoMaterialError;

  fn try_from(public_key_bytes: &[u8]) -> Result<Self, Self::Error> {
    let public_key_bytes: [u8; PUBLIC_KEY_SIZE] = public_key_bytes
      .try_into()
      .map_err(|_| traits::CryptoMaterialError::WrongLengthError)?;
    Ok(Self(public_key_bytes))
  }
}

impl traits::ValidKey for PrivateKeyBytes {
  fn to_bytes(&self) -> Vec<u8> {
    self.0.to_vec()
  }
}

impl traits::ValidKey for PublicKeyBytes {
  fn to_bytes(&self) -> Vec<u8> {
    self.0.to_vec()
  }
}

impl traits::PrivateKey for PrivateKeyBytes {
  type PublicKeyMaterial = PublicKeyBytes;
}

impl traits::PublicKey for PublicKeyBytes {
  type PrivateKeyMaterial = PrivateKeyBytes;
}

impl From<&PrivateKeyBytes> for PublicKeyBytes {
  fn from(private_key: &PrivateKeyBytes) -> Self {
    private_key.public_key()
  }
}

// TODO: do we need this?
impl std::convert::From<&PublicKey> for PublicKeyBytes {
  fn from(public_key: &PublicKey) -> Self {
    Self(public_key.as_bytes().to_owned())
  }
}

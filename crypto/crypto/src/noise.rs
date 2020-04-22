// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Noise is a [protocol framework](https://noiseprotocol.org/) which we use in Libra to
//! encrypt and authenticate communications between nodes of the network.
//!
//! This file implements a stripped-down version of Noise_IK_25519_AESGCM_SHA256.
//! This means that only the parts that we care about (the IK handshake) are implemented.
//!
//! Note that to benefit from hardware support for AES, you must build this crate with the following
//! flags: `RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"`.
//!
//! Usage example:
//!
//! ```
//! use libra_crypto::{noise::NoiseConfig, x25519, traits::*};
//! use rand::prelude::*;
//!
//! # fn main() -> Result<(), libra_crypto::noise::NoiseError> {
//! let mut rng = rand::thread_rng();
//! let initiator_static = x25519::PrivateKey::generate(&mut rng);
//! let responder_static = x25519::PrivateKey::generate(&mut rng);
//! let responder_public = responder_static.public_key();
//!
//! let initiator = NoiseConfig::new(initiator_static);
//! let responder = NoiseConfig::new(responder_static);
//!
//! let (initiator_state, first_message) = initiator
//!   .initiate_connection(&mut rng, b"prologue", &responder_public, None)?;
//! let (second_message, remote_static, _, mut responder_session) = responder
//!   .respond_to_client_and_finalize(&mut rng, b"prologue", &first_message, None)?;
//! let (_, mut initiator_session) = initiator
//!   .finalize_connection(initiator_state, &second_message)?;
//!
//! let encrypted_message = initiator_session
//!   .write_message(b"hello world")
//!   .expect("session should not be closed");
//! let received_message = responder_session
//!   .read_message(&encrypted_message)
//!   .expect("session should not be closed");
//! # Ok(())
//! # }
//! ```
//!

use std::convert::TryFrom as _;
use std::io::{Cursor, Read as _, Write};

use crate::traits::{Uniform as _, ValidKey as _};
use crate::{hash::HashValue, hkdf::Hkdf, x25519 as x25519_intern};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    Aes256Gcm,
};
use sha2::Digest;
use thiserror::Error;

//
// Useful constants
// ----------------
//

/// A noise message cannot be larger than 65535 bytes as per the specification.
pub const MAX_SIZE_NOISE_MSG: usize = 65535;

/// The authentication tag length of AES-GCM.
pub const AES_GCM_TAGLEN: usize = 16;

/// The only Noise handshake protocol that we implement in this file.
const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_AESGCM_SHA256\0\0\0\0";

/// The nonce size we use for AES-GCM.
const AES_NONCE_SIZE: usize = 12;

/// This implementation relies on the fact that the hash function used has a 256-bit output
#[rustfmt::skip]
const _: [(); 0 - !{ const ASSERT: bool = HashValue::LENGTH == 32; ASSERT } as usize] = [];

//
// Errors
// ------
//

/// A NoiseError enum represents the different types of error that noise can return to users of the crate
#[derive(Debug, Error)]
pub enum NoiseError {
    /// the received message is too short to contain the expected data
    #[error("noise: the received message is too short to contain the expected data")]
    MsgTooShort,

    /// HKDF has failed (in practice there is no reason for HKDF to fail)
    #[error("noise: HKDF has failed")]
    Hkdf,

    /// encryption has failed (in practice there is no reason for encryption to fail)
    #[error("noise: encryption has failed")]
    Encrypt,

    /// could not decrypt the received data (most likely the data was tampered with
    #[error("noise: could not decrypt the received data")]
    Decrypt,

    /// the public key received is of the wrong format
    #[error("noise: the public key received is of the wrong format")]
    WrongPublicKeyReceived,

    /// session was closed due to decrypt error
    #[error("noise: session was closed due to decrypt error")]
    SessionClosed,

    /// the payload that we are trying to send is too large
    #[error("noise: the payload that we are trying to send is too large")]
    PayloadTooLarge,

    /// the message we received is too large
    #[error("noise: the message we received is too large")]
    ReceivedMsgTooLarge,

    /// can't write in given buffer
    #[error("noise: can't write in given buffer")]
    CantWriteBuffer,
}

//
// helpers
// -------
//

fn hash(data: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(data).to_vec()
}

fn hkdf(ck: &[u8], dh_output: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), NoiseError> {
    let dh_output = dh_output.unwrap_or_else(|| &[]);
    let hkdf_output = Hkdf::<sha2::Sha256>::extract_then_expand(Some(ck), dh_output, None, 64);

    let hkdf_output = hkdf_output.map_err(|_| NoiseError::Hkdf)?;
    let (k1, k2) = hkdf_output.split_at(32);
    Ok((k1.to_vec(), k2.to_vec()))
}

fn mix_hash(h: &mut Vec<u8>, data: &[u8]) {
    h.extend_from_slice(data);
    *h = hash(h);
}

fn mix_key(ck: &mut Vec<u8>, dh_output: &[u8]) -> Result<Vec<u8>, NoiseError> {
    let (new_ck, k) = hkdf(ck, Some(dh_output))?;
    *ck = new_ck;
    Ok(k)
}

fn checked_vec_to_public_key(bytes: &[u8]) -> Result<x25519_intern::PublicKey, NoiseError> {
    x25519_intern::PublicKey::try_from(bytes).map_err(|_| NoiseError::WrongPublicKeyReceived)
}

//
// Noise implementation
// --------------------
//

/// A key holder structure used for both initiators and responders.
pub struct NoiseConfig {
    private_key: x25519_intern::PrivateKey,
    public_key: x25519_intern::PublicKey,
}

impl std::fmt::Debug for NoiseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // only display private if we're testing
        let private_key = if cfg!(test) {
            let private_key = lcs::to_bytes(&self.private_key).unwrap();
            hex::encode(&private_key)
        } else {
            "{private key removed}".to_string()
        };

        let public_key = lcs::to_bytes(self.public_key.as_slice()).unwrap();
        let public_key = hex::encode(&public_key);

        write!(
            f,
            "NoiseConfig {{ private_key: {}, public_key: {} }}",
            private_key, public_key
        )
    }
}

/// Refer to the Noise protocol framework specification in order to understand these fields.
pub struct InitiatorHandshakeState {
    /// rolling hash
    h: Vec<u8>,
    /// chaining key
    ck: Vec<u8>,
    /// ephemeral key
    e: x25519_intern::PrivateKey,
}

/// Refer to the Noise protocol framework specification in order to understand these fields.
pub struct ResponderHandshakeState {
    /// rolling hash
    h: Vec<u8>,
    /// chaining key
    ck: Vec<u8>,
    /// remote static key received
    rs: x25519_intern::PublicKey,
    /// remote ephemeral key receiced
    re: x25519_intern::PublicKey,
}

impl NoiseConfig {
    /// A peer must create a NoiseConfig through this function before being able to connect with other peers.
    pub fn new(private_key: x25519_intern::PrivateKey) -> Self {
        // we could take a public key as argument, and it would be faster, but this is cleaner
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    //
    // Initiator
    // ---------

    /// An initiator can use this function to initiate a handshake with a known responder.
    pub fn initiate_connection(
        &self,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
        prologue: &[u8],
        remote_public: &x25519_intern::PublicKey,
        payload: Option<&[u8]>,
    ) -> Result<(InitiatorHandshakeState, Vec<u8>), NoiseError> {
        // checks
        if let Some(payload) = payload {
            if payload.len()
                > MAX_SIZE_NOISE_MSG - 2 * x25519_intern::PUBLIC_KEY_SIZE - 2 * AES_GCM_TAGLEN
            {
                return Err(NoiseError::PayloadTooLarge);
            }
        }

        // initialize
        let mut h = PROTOCOL_NAME.to_vec();
        let mut ck = PROTOCOL_NAME.to_vec();
        let re = remote_public; // for naming consistency with the specification
        mix_hash(&mut h, &prologue);
        mix_hash(&mut h, re.as_slice());

        // -> e
        let e = if cfg!(test) {
            let mut ephemeral_private = [0u8; x25519_intern::PUBLIC_KEY_SIZE];
            rng.fill_bytes(&mut ephemeral_private);
            x25519_intern::PrivateKey::try_from(ephemeral_private).unwrap()
        } else {
            x25519_intern::PrivateKey::generate(rng)
        };

        let e_pub = e.public_key();

        mix_hash(&mut h, e_pub.as_slice());
        let mut msg = e_pub.to_bytes();

        // -> es
        let dh_output = e.diffie_hellman(re);
        let k = mix_key(&mut ck, &dh_output)?;

        // -> s
        let aead = Aes256Gcm::new(GenericArray::clone_from_slice(&k));

        let msg_and_ad = Payload {
            msg: self.public_key.as_slice(),
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_static = aead.encrypt(nonce, msg_and_ad).unwrap(); // this API cannot fail
        mix_hash(&mut h, &encrypted_static);
        msg.extend_from_slice(&encrypted_static);

        // -> ss
        let dh_output = self.private_key.diffie_hellman(re);
        let k = mix_key(&mut ck, &dh_output)?;

        // -> payload
        let aead = Aes256Gcm::new(GenericArray::clone_from_slice(&k));

        let msg_and_ad = Payload {
            msg: payload.unwrap_or_else(|| &[]),
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_payload = aead
            .encrypt(nonce, msg_and_ad)
            .map_err(|_| NoiseError::Encrypt)?;
        mix_hash(&mut h, &encrypted_payload);
        msg.extend_from_slice(&encrypted_payload);

        // return
        let handshake_state = InitiatorHandshakeState { h, ck, e };
        Ok((handshake_state, msg))
    }

    /// A client can call this to finalize a connection, after receiving an answer from a server.
    pub fn finalize_connection(
        &self,
        handshake_state: InitiatorHandshakeState,
        received_message: &[u8],
    ) -> Result<(Vec<u8>, NoiseSession), NoiseError> {
        // checks
        if received_message.len() > MAX_SIZE_NOISE_MSG {
            return Err(NoiseError::ReceivedMsgTooLarge);
        }
        // retrieve handshake state
        let InitiatorHandshakeState { mut h, mut ck, e } = handshake_state;

        // <- e
        let mut re = [0u8; x25519_intern::PUBLIC_KEY_SIZE];
        let mut cursor = Cursor::new(received_message);
        cursor
            .read_exact(&mut re)
            .map_err(|_| NoiseError::MsgTooShort)?;
        mix_hash(&mut h, &re);
        let re = x25519_intern::PublicKey::from(re);

        // <- ee
        let dh_output = e.diffie_hellman(&re);
        mix_key(&mut ck, &dh_output)?;

        // <- se
        let dh_output = self.private_key.diffie_hellman(&re);
        let k = mix_key(&mut ck, &dh_output)?;

        // <- payload
        let offset = cursor.position() as usize;
        let received_encrypted_payload = &cursor.into_inner()[offset..];

        let aead = Aes256Gcm::new(GenericArray::clone_from_slice(&k));

        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let ct_and_ad = Payload {
            msg: received_encrypted_payload,
            aad: &h,
        };
        let received_payload = match aead.decrypt(nonce, ct_and_ad) {
            Ok(res) => res,
            Err(_) if cfg!(feature = "fuzzing") => Vec::new(),
            Err(_) => {
                return Err(NoiseError::Decrypt);
            }
        };

        // split
        let (k1, k2) = hkdf(&ck, None)?;
        let session = NoiseSession::new(k1, k2);

        //
        Ok((received_payload, session))
    }

    //
    // Responder
    // ---------
    // There are two ways to use this API:
    // - either use `parse_client_init_message()` followed by `respond_to_client()`
    // - or use the all-in-one `respond_to_client_and_finalize()`
    //
    // the reason for the first deconstructed API is that we might want to do
    // some validation of the received initiator's public key which might
    //

    /// TODO: doc
    pub fn parse_client_init_message(
        &self,
        prologue: &[u8],
        received_message: &[u8],
    ) -> Result<
        (
            x25519_intern::PublicKey, // initiator's public key
            ResponderHandshakeState,  // state to be used in respond_to_client
            Vec<u8>,                  // payload received
        ),
        NoiseError,
    > {
        // checks
        if received_message.len() > MAX_SIZE_NOISE_MSG {
            return Err(NoiseError::ReceivedMsgTooLarge);
        }
        // initialize
        let mut h = PROTOCOL_NAME.to_vec();
        let mut ck = PROTOCOL_NAME.to_vec();
        mix_hash(&mut h, prologue);
        mix_hash(&mut h, self.public_key.as_slice());

        // buffer message received
        let mut cursor = Cursor::new(received_message);

        // <- e
        let mut re = [0u8; x25519_intern::PUBLIC_KEY_SIZE];
        cursor
            .read_exact(&mut re)
            .map_err(|_| NoiseError::MsgTooShort)?;
        mix_hash(&mut h, &re);
        let re = x25519_intern::PublicKey::from(re);

        // <- es
        let dh_output = self.private_key.diffie_hellman(&re);
        let k = mix_key(&mut ck, &dh_output)?;

        // <- s
        let mut encrypted_remote_static = [0u8; x25519_intern::PUBLIC_KEY_SIZE + AES_GCM_TAGLEN];
        cursor
            .read_exact(&mut encrypted_remote_static)
            .map_err(|_| NoiseError::MsgTooShort)?;

        let aead = Aes256Gcm::new(GenericArray::clone_from_slice(&k));

        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let ct_and_ad = Payload {
            msg: &encrypted_remote_static,
            aad: &h,
        };
        let rs = match aead.decrypt(nonce, ct_and_ad) {
            Ok(res) => res,
            Err(_) if cfg!(feature = "fuzzing") => encrypted_remote_static[..32].to_vec(),
            Err(_) => {
                return Err(NoiseError::Decrypt);
            }
        };
        let rs = checked_vec_to_public_key(&rs)?;
        mix_hash(&mut h, &encrypted_remote_static);

        // <- ss
        let dh_output = self.private_key.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;

        // <- payload
        let offset = cursor.position() as usize;
        let received_encrypted_payload = &cursor.into_inner()[offset..];

        let aead = Aes256Gcm::new(GenericArray::clone_from_slice(&k));

        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let ct_and_ad = Payload {
            msg: received_encrypted_payload,
            aad: &h,
        };
        let received_payload = match aead.decrypt(nonce, ct_and_ad) {
            Ok(res) => res,
            Err(_) if cfg!(feature = "fuzzing") => Vec::new(),
            Err(_) => {
                return Err(NoiseError::Decrypt);
            }
        };
        mix_hash(&mut h, received_encrypted_payload);

        // return
        let handshake_state = ResponderHandshakeState { h, ck, rs, re };
        Ok((rs, handshake_state, received_payload))
    }

    /// TODO: doc
    pub fn respond_to_client(
        &self,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
        handshake_state: ResponderHandshakeState,
        payload: Option<&[u8]>,
        response_buffer: &mut impl Write,
    ) -> Result<NoiseSession, NoiseError> {
        // checks
        if let Some(payload) = payload {
            if payload.len() > MAX_SIZE_NOISE_MSG - x25519_intern::PUBLIC_KEY_SIZE - AES_GCM_TAGLEN
            {
                return Err(NoiseError::PayloadTooLarge);
            }
        }
        // retrieve handshake state
        let ResponderHandshakeState {
            mut h,
            mut ck,
            rs,
            re,
        } = handshake_state;

        // -> e
        let e = if cfg!(test) {
            let mut ephemeral_private = [0u8; 32];
            rng.fill_bytes(&mut ephemeral_private);
            x25519_intern::PrivateKey::from(ephemeral_private)
        } else {
            x25519_intern::PrivateKey::generate(rng)
        };

        let e_pub = e.public_key();

        mix_hash(&mut h, e_pub.as_slice());
        response_buffer
            .write(e_pub.as_slice())
            .map_err(|_| NoiseError::CantWriteBuffer)?;

        // -> ee
        let dh_output = e.diffie_hellman(&re);
        mix_key(&mut ck, &dh_output)?;

        // -> se
        let dh_output = e.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;

        // -> payload
        let aead = Aes256Gcm::new(GenericArray::clone_from_slice(&k));

        let msg_and_ad = Payload {
            msg: payload.unwrap_or_else(|| &[]),
            aad: &h,
        };
        let nonce = GenericArray::from_slice(&[0u8; AES_NONCE_SIZE]);
        let encrypted_payload = aead
            .encrypt(nonce, msg_and_ad)
            .map_err(|_| NoiseError::Encrypt)?;
        mix_hash(&mut h, &encrypted_payload);
        response_buffer
            .write(&encrypted_payload)
            .map_err(|_| NoiseError::CantWriteBuffer)?;

        // split
        let (k1, k2) = hkdf(&ck, None)?;
        let session = NoiseSession::new(k2, k1);

        //
        Ok(session)
    }

    /// This function is a one-call that replaces calling the two functions parse_client_init_message
    /// and respond_to_client consecutively
    pub fn respond_to_client_and_finalize(
        &self,
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
        prologue: &[u8],
        received_message: &[u8],
        payload: Option<&[u8]>,
        response_buffer: &mut impl Write,
    ) -> Result<
        (
            x25519_intern::PublicKey, // the public key of the initiator
            Vec<u8>,                  // the payload the initiator sent
            NoiseSession,             // The created session
        ),
        NoiseError,
    > {
        let (remote_public_key, handshake_state, received_payload) =
            self.parse_client_init_message(prologue, received_message)?;
        let session = self.respond_to_client(rng, handshake_state, payload, response_buffer)?;
        Ok((remote_public_key, received_payload, session))
    }
}

//
// Post-Handshake
// --------------

/// A NoiseSession is produced after a successful Noise handshake, and can be use to encrypt and decrypt messages to the other peer.
pub struct NoiseSession {
    /// a session can be marked as invalid if it has seen a decryption failure
    valid: bool,
    //    /// the public key of the other peer
    //    remote_public_key: x25519_intern::PublicKey,
    /// key used to encrypt messages to the other peer
    write_key: Vec<u8>,
    /// associated nonce (in practice the maximum u64 value cannot be reached)
    write_nonce: u64,
    /// key used to decrypt messages received from the other peer
    read_key: Vec<u8>,
    /// associated nonce (in practice the maximum u64 value cannot be reached)
    read_nonce: u64,
}

impl NoiseSession {
    fn new(write_key: Vec<u8>, read_key: Vec<u8>) -> Self {
        Self {
            valid: true,
            write_key,
            write_nonce: 0,
            read_key,
            read_nonce: 0,
        }
    }
    /*
        pub fn get_remote_static(&self) -> x25519::PublicKey {
            self.remote_public_key
        }
    */
    /// encrypts a message for the other peers (post-handshake)
    pub fn write_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        // checks
        if !self.valid {
            return Err(NoiseError::SessionClosed);
        }
        if plaintext.len() > MAX_SIZE_NOISE_MSG - AES_GCM_TAGLEN {
            return Err(NoiseError::PayloadTooLarge);
        }

        // encrypt
        let aead = Aes256Gcm::new(GenericArray::clone_from_slice(&self.write_key));

        let msg_and_ad = Payload {
            msg: plaintext,
            aad: &[],
        };
        let mut nonce = [0u8; 4].to_vec();
        nonce.extend_from_slice(&self.write_nonce.to_be_bytes());
        let nonce = GenericArray::from_slice(&nonce);
        let ciphertext = aead.encrypt(nonce, msg_and_ad).unwrap(); // this API cannot fail

        // increment nonce
        self.write_nonce += 1;

        //
        Ok(ciphertext)
    }

    /// decrypts a message from the other peer (post-handshake)
    pub fn read_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        // checks
        if !self.valid {
            return Err(NoiseError::SessionClosed);
        }
        if ciphertext.len() > MAX_SIZE_NOISE_MSG {
            return Err(NoiseError::ReceivedMsgTooLarge);
        }

        // decrypt
        let aead = Aes256Gcm::new(GenericArray::clone_from_slice(&self.read_key));

        let mut nonce = [0u8; 4].to_vec();
        nonce.extend_from_slice(&self.read_nonce.to_be_bytes());
        let nonce = GenericArray::from_slice(&nonce);
        let ct_and_ad = Payload {
            msg: &ciphertext,
            aad: &[],
        };
        let plaintext = aead.decrypt(nonce, ct_and_ad).map_err(|_| {
            self.valid = false;
            NoiseError::Decrypt
        })?;

        // increment nonce
        self.read_nonce += 1;

        //
        Ok(plaintext)
    }
}

impl std::fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoiseSession[...]")
    }
}

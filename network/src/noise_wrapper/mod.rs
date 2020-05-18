// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This crate implements wrappers around our [Noise][noise] implementation.
//! Noise is used to encrypt and authenticate connections between peers.
//! Specifically, we use the [Noise IK][ik] handshake which is a one round-trip protocol
//! (the client sends one message, then the server responds).
//! For more information about Noise and our implementation, refer to the [crypto] crate.
//!
//! Usage example:
//!
//! ```
//! use noise_wrapper::handshake::NoiseWrapper;
//! use futures::{executor, future, io::{AsyncReadExt, AsyncWriteExt}};
//! use memsocket::MemorySocket;
//! use crate::NetworkPublicKeys;
//! use libra_crypto::{x25519, ed25519, Uniform, PrivateKey, test_utils::TEST_SEED};
//! use rand::{rngs::StdRng, SeedableRng};
//! use libra_types::PeerId;
//! use libra_config::config::NetworkPeerInfo;
//! use std::{collections::HashMap, sync::{Arc, RwLock}};
//!
//! # fn example() -> std::io::Result<()> {
//! // create client and server NoiseWrapper
//! let mut rng = StdRng::from_seed(TEST_SEED);
//! let client_private = x25519::PrivateKey::generate(&mut rng);
//! let client_public = client_private.public_key();
//! let server_private = x25519::PrivateKey::generate(&mut rng);
//! let server_public = server_private.public_key();
//! let client = NoiseWrapper::new(client_private);
//! let server = NoiseWrapper::new(server_private);
//!
//! // create list of trusted peers
//! let mut trusted_peers = Arc::new(RwLock::new(HashMap::new()));
//! {
//!     let dummy_signing_key = ed25519::Ed25519PrivateKey::generate(&mut rng);
//!     trusted_peers.read().unwrap().insert(PeerId::random(), NetworkPublicKeys {
//!        signing_public_key: dummy_signing_key.public_key(),
//!        identity_public_key: client_public,
//!     });
//! }
//!
//! // use an in-memory socket as example
//! let (dialer_socket, listener_socket) = MemorySocket::new_pair();
//! 
//! // perform the handshake
//! let (client_session, server_session) = executor::block_on(future::join(
//!    client.dial(dialer_socket, server_public),
//!    server.accept(listener_socket, Some(&trusted_peers)),
//! ));
//!
//! let mut client_session = client_session?;
//! let mut server_Session = server_session?;
//!
//! // client -> server
//! executor::block_on(client.write_all(b"client hello"))?;
//! executor::block_on(client.flush())?;
//!
//! let mut buf = [0; 12];
//! executor::block_on(server.read_exact(&mut buf))?;
//! assert_eq!(&buf, b"client hello");
//! 
//! // server -> client
//! executor::block_on(server.write_all(b"server hello"))?;
//! executor::block_on(server.flush())?;
//!
//! let mut buf = [0; 12];
//! executor::block_on(client.read_exact(&mut buf))?;
//! assert_eq!(&buf, b"server hello");
//!
//! # Ok(())
//! # }
//!
//!
//! ```
//!
//! [noise]: http://noiseprotocol.org/
//! [ik]: https://noiseexplorer.com/patterns/IK
//! [crypto]: ../libra_crypto/noise/index.html

pub mod handshake;
pub mod socket;

pub use handshake::NoiseWrapper;
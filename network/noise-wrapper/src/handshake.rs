// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0


//! The handshake module implements the handshake part of the protocol.
//! This module also implements additional anti-DoS mitigation, 
//! by including a timestamp in each handshake initialization message.
//! Refer to the module's documentation for more information.
//! A successful handshake returns a `NoiseSocket` which is defined in [socket] module.
//!
//! [socket]: crate::socket

use futures::{
  future::poll_fn,
  io::{AsyncRead, AsyncWrite},
};
use once_cell::sync::Lazy;
use std::{
  collections::HashMap,
  io,
  pin::Pin,
  sync::{Arc, Mutex, RwLock},
  time,
};

use libra_config::config::NetworkPeerInfo;
use libra_crypto::{noise, x25519};
use libra_types::PeerId;
use netcore::{
  negotiate::{negotiate_inbound, negotiate_outbound_interactive},
  transport::ConnectionOrigin,
};
use libra_logger::prelude::*;

use crate::socket::{poll_read_exact, poll_write_all, NoiseSocket};



// Timestamp
// --------
// We parse the client message and then enforce two things:
// - the client sent us a timestamp in a range [-60s, +10s]
// - the client is not re-using an older timestamp from that range
//
// if these are invalid, we avoid computing crypto to perform the answer
// if these are valid, we store the new timestamp (even if it's older than the last received)
// the last point assumes that a real client would not do this.
// this is not a measure against real validators spamming us

/// we're willing to tolerate a client timestamp 10 seconds in the future
const MAX_FUTURE_TIMESTAMP: u64 = 10;

/// we store client timestamps (to prevent replay) for up to 60 seconds
const EXPIRATION_TIMESTAMP: u64 = 60;

/// hashmap to store client timestamps if a connection succeeds
static LAST_SEEN_CLIENT_TIMESTAMPS: Lazy<Mutex<HashMap<x25519::PublicKey, u64>>> =
  Lazy::new(|| Mutex::new(HashMap::new()));

// Noise Wrapper
// -------------
// Noise by default is not aware of the above or lower protocol layers,
// We thus need to build this wrapper around Noise to both:
//
// - fragment messages that need to be encrypted by noise (due to its maximum 65535-byte messages)
// - understand how long noise messages we send and receive are,
//   in order to pass them to the noise implementaiton
//

/// TODO: why do we expose this to the outer protocol?
const NOISE_PROTOCOL: &[u8] = b"/noise_ik_25519_aesgcm_sha256/1.0.0";

/// The Noise configuration to be used to perform a protocol upgrade on an underlying socket.
pub struct NoiseWrapper(noise::NoiseConfig);

impl NoiseWrapper {
    /// Create a new NoiseConfig with the provided keypair
    pub fn new(key: x25519::PrivateKey) -> Self {
        Self(noise::NoiseConfig::new(key))
    }

    /// Create a new NoiseConfig with an ephemeral static key.
    #[cfg(feature = "testing")]
    pub fn new_random(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> Self {
        use libra_crypto::Uniform;
        let key = x25519::PrivateKey::generate(rng);
        Self(noise::NoiseConfig::new(key))
    }

    /// Perform a protocol upgrade on an underlying connection. In addition perform the noise IX
    /// handshake to establish a noise session and exchange static public keys. Upon success,
    /// returns the static public key of the remote as well as a NoiseSocket.
    pub async fn upgrade_connection<TSocket>(
        &self,
        socket: TSocket,
        origin: ConnectionOrigin,
        remote_public_key: x25519::PublicKey,
        trusted_peers: Option<&Arc<RwLock<HashMap<PeerId, NetworkPeerInfo>>>>,
    ) -> io::Result<(x25519::PublicKey, NoiseSocket<TSocket>)>
    where
        TSocket: AsyncRead + AsyncWrite + Unpin,
    {
        // Perform protocol negotiation
        let (socket, proto) = match origin {
            ConnectionOrigin::Outbound => {
                negotiate_outbound_interactive(socket, [NOISE_PROTOCOL]).await?
            }
            ConnectionOrigin::Inbound => negotiate_inbound(socket, [NOISE_PROTOCOL]).await?,
        };

        // check that the correct protocol was negotiated
        if proto != NOISE_PROTOCOL {
            if cfg!(test) {
                panic!("noise: incorrect protocol negotiated");
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "noise: incorrect protocol negotiated",
                ));
            }
        }

        // perform the noise handshake
        let socket = match origin {
            ConnectionOrigin::Outbound => self.dial(socket, remote_public_key).await?,
            ConnectionOrigin::Inbound => self.accept(socket, trusted_peers).await?,
        };

        // return remote public key with a socket including the noise session
        let remote_public_key = socket.get_remote_static();
        return Ok((remote_public_key, socket));
    }

    pub async fn dial<TSocket>(
        &self,
        mut socket: TSocket,
        remote_public_key: x25519::PublicKey,
    ) -> io::Result<NoiseSocket<TSocket>>
    where
        TSocket: AsyncRead + AsyncWrite + Unpin,
    {
        // create prologue as current timestamp in seconds, and send it
        let now: u64 = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .expect("system clock should work")
            .as_secs();
        let prologue = now.to_le_bytes(); // 5 -> [0, 0, 0, 0, 0, 0, 0, 5]
        poll_fn(|context| poll_write_all(context, Pin::new(&mut socket), &prologue, &mut 0))
            .await?;
        println!("client: wrote timestamp");

        // create first handshake message  (-> e, es, s, ss)
        let mut rng = rand::thread_rng();
        let mut first_message = [0u8; noise::handshake_init_msg_len(0)];
        let initiator_state = self
            .0
            .initiate_connection(
                &mut rng,
                &prologue,
                remote_public_key,
                None,
                &mut first_message,
            )
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("noise: wrong input passed {}", e),
                )
            })?;
            println!("client: initiated connection");

        // write the first handshake message
        poll_fn(|context| poll_write_all(context, Pin::new(&mut socket), &first_message, &mut 0))
            .await?;
            println!("client: wrote first handshake message");

        // flush
        poll_fn(|context| Pin::new(&mut socket).poll_flush(context)).await?;
        println!("client: flushed first handshake message");

        // receive the server's response (<- e, ee, se)
        let mut server_response = [0u8; noise::handshake_resp_msg_len(0)];
        poll_fn(|context| {
            poll_read_exact(context, Pin::new(&mut socket), &mut server_response, &mut 0)
        })
        .await?;
        println!("client: read second handshake message");

        // parse the server's response
        // TODO: security logging here? (mimoo)
        let (_, session) = self
            .0
            .finalize_connection(initiator_state, &server_response)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("noise: wrong message received {}", e),
                )
            })?;

        // finalize the connection
        Ok(NoiseSocket::new(socket, session))
    }

    pub async fn accept<TSocket>(
        &self,
        mut socket: TSocket,
        trusted_peers: Option<&Arc<RwLock<HashMap<PeerId, NetworkPeerInfo>>>>,
    ) -> io::Result<NoiseSocket<TSocket>>
    where
        TSocket: AsyncRead + AsyncWrite + Unpin,
    {
      println!("server: starting listener");
        // receives prologue as the client timestamp in seconds
        let mut prologue = [0u8; 8];
        poll_fn(|context| poll_read_exact(context, Pin::new(&mut socket), &mut prologue, &mut 0))
            .await?;
            println!("server: read timestamp");
        let client_timestamp_u64 = u64::from_le_bytes(prologue);
        let client_timestamp = time::Duration::from_secs(client_timestamp_u64);

        // check the client timestamp
        // TODO: security logging (mimoo)
        let now = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .expect("system clock should work");
        if client_timestamp > now
            && client_timestamp - now > time::Duration::from_secs(MAX_FUTURE_TIMESTAMP)
        {
            // if the client timestamp is too far in the future, abort
            println!("server error: 1");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "noise: client initiated connection with a timestamp too far in the future: {}",
                    client_timestamp_u64
                ),
            ));
        } else if now.checked_sub(client_timestamp).unwrap()
            > time::Duration::from_secs(EXPIRATION_TIMESTAMP)
        {
          println!("server error: 2");
            // if the client timestamp is expired, abort
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "noise: client initiated connection with an expired timestamp: {}",
                    client_timestamp_u64
                ),
            ));
        }

        // receive the initiation message
        println!("server: waiting for first handshake message");
        let mut client_init_message = [0u8; noise::handshake_init_msg_len(0)];
        poll_fn(|context| {
            poll_read_exact(
                context,
                Pin::new(&mut socket),
                &mut client_init_message,
                &mut 0,
            )
        })
        .await?;
        println!("server: received first handshake message");

        // parse it
        let (their_public_key, handshake_state, _) = self
            .0
            .parse_client_init_message(&prologue, &client_init_message)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("noise: wrong message received {}", e),
                )
            })?;
            println!("server: parsed first handshake message");

        // make sure the public key is a validator before continuing (if we're in the validator network)
        if let Some(trusted_peers) = trusted_peers {
            let found = trusted_peers
                .read()
                .unwrap()
                .iter()
                .find(|(_peer_id, public_keys)| public_keys.identity_public_key == their_public_key)
                .is_some();
            if !found {
                // TODO: security logging (mimoo)
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "noise: validator client initiated connection with an unknown public key: {}",
                        their_public_key
                    ),
                ));
            }
        }

        // check the timestamp is not a replay
        {
            let timestamps = LAST_SEEN_CLIENT_TIMESTAMPS.lock().unwrap();
            if let Some(timestamp) = timestamps.get(&their_public_key) {
                // TODO: security logging the ip + blocking the ip? (mimoo)
                if timestamp == &client_timestamp_u64 {
                    return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "noise: client initiated connection with a timestamp already seen before: {}",
                        client_timestamp_u64
                    ),
                ));
                }
            }
        }

        // construct and send the response
        let mut rng = rand::thread_rng();
        let mut server_response = [0u8; noise::handshake_resp_msg_len(0)];
        let session = self
            .0
            .respond_to_client(&mut rng, handshake_state, None, &mut server_response)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("noise: wrong message received {}", e),
                )
            })?;
            println!("server: constructed the response");
        poll_fn(|context| poll_write_all(context, Pin::new(&mut socket), &server_response, &mut 0))
            .await?;
        println!("server: wrote the response");

        // the connection succeeded, store the client timestamp for replay prevention
        {
            let mut timestamps = LAST_SEEN_CLIENT_TIMESTAMPS.lock().unwrap();
            timestamps
                .entry(their_public_key)
                .and_modify(|e| *e = client_timestamp_u64)
                .or_insert(client_timestamp_u64);
        }

        // finalize the connection
        Ok(NoiseSocket::new(socket, session))
    }
}


//
// Tests
// -----
//

#[cfg(test)]
mod test {
    use super::*;

    use crate::handshake::NoiseWrapper;
    use futures::{
        executor::block_on,
        future::join,
        io::{AsyncReadExt, AsyncWriteExt},
    };
    use libra_crypto::{test_utils::TEST_SEED, x25519};
    use memsocket::MemorySocket;
    use std::io;
    use std::sync::{Arc, RwLock};
    use std::collections::HashMap;
    use libra_types::PeerId;
    use libra_config::config::NetworkPeerInfo;

    use rand::SeedableRng as _;
    use libra_crypto::traits::Uniform as _;

    // TODO: move the handshake tests to handshake.rs

    /// helper to setup two testing peers
    fn build_peers() -> (
        (NoiseWrapper, x25519::PublicKey),
        (NoiseWrapper, x25519::PublicKey),
    ) {
        let mut rng = ::rand::rngs::StdRng::from_seed(TEST_SEED);

        let client_private = x25519::PrivateKey::generate(&mut rng);
        let client_public = client_private.public_key();

        let server_private = x25519::PrivateKey::generate(&mut rng);
        let server_public = server_private.public_key();

        let client = NoiseWrapper::new(client_private);
        let server = NoiseWrapper::new(server_private);

        (
            (client, client_public),
            (server, server_public),
        )
    }

    /// helper to perform a noise handshake with two peers
    fn perform_handshake(
        client: NoiseWrapper,
        server_public_key: x25519::PublicKey,
        server: NoiseWrapper,
        trusted_peers: Option<&Arc<RwLock<HashMap<PeerId, NetworkPeerInfo>>>>,
    ) -> io::Result<(NoiseSocket<MemorySocket>, NoiseSocket<MemorySocket>)> {
        // create an in-memory socket for testing
        let (dialer_socket, listener_socket) = MemorySocket::new_pair();

        // perform the handshake
        let (client_session, server_session) = block_on(join(
            client.dial(dialer_socket, server_public_key),
            server.accept(listener_socket, trusted_peers),
        ));

        //
        Ok((client_session?, server_session?))
    }

    #[test]
    fn test_handshake() {
        // perform handshake with two testing peers
        let ((client, client_public), (server, server_public)) =
            build_peers();
        let (client, server) = perform_handshake(client, server_public, server, None).unwrap();

        assert_eq!(client.get_remote_static(), server_public,);
        assert_eq!(server.get_remote_static(), client_public,);
    }
  }
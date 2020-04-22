// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! [Noise protocol framework][noise] support for use in Libra.
//!
//! The main feature of this module is [`NoiseSocket`](crate::socket::NoiseSocket) which
//! provides wire-framing for noise payloads.  Currently the only handshake pattern supported is IX.
//!
//! [noise]: http://noiseprotocol.org/

use futures::{
    future::poll_fn,
    io::{AsyncRead, AsyncWrite},
};
use libra_crypto::{noise, x25519, ValidKey};
use netcore::{
    negotiate::{negotiate_inbound, negotiate_outbound_interactive},
    transport::ConnectionOrigin,
};
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    time,
};

mod socket;

#[cfg(any(feature = "fuzzing", test))]
pub use self::socket::noise_fuzzing;

pub use self::socket::NoiseSocket;

use self::socket::{poll_read_exact, poll_write_all};

/// TODO: doc
const NOISE_PROTOCOL: &[u8] = b"/noise_ik_25519_aesgcm_sha256/1.0.0";

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
type Timestamps = Mutex<HashMap<x25519::PublicKey, u64>>;
static LAST_SEEN_CLIENT_TIMESTAMPS: Lazy<Timestamps> = Lazy::new(|| Mutex::new(HashMap::new()));

/// The Noise protocol configuration to be used to perform a protocol upgrade on an underlying
/// socket.
pub struct NoiseConfig(noise::NoiseConfig);

impl NoiseConfig {
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
        remote_public_key: &x25519::PublicKey,
    ) -> io::Result<(Vec<u8>, NoiseSocket<TSocket>)>
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
                panic!();
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "incorrect protocol",
                ));
            }
        }

        match origin {
            ConnectionOrigin::Outbound => {
                let socket = self.dial(socket, remote_public_key).await?;
                return Ok(socket);
            }
            ConnectionOrigin::Inbound => {
                let (socket, remote_public_key) = self.accept(socket).await?;
                return Ok(socket);
            }
        };
    }

    pub async fn dial<TSocket>(
        mut self,
        socket: TSocket,
        remote_public_key: &x25519::PublicKey,
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
        poll_fn(|context| poll_write_all(context, Pin::new(&mut socket), &prologue, 0)).await?;

        // create first handshake message  (-> e, es, s, ss)
        let mut rng = rand::thread_rng();
        // TODO: calculate size of first msg without payload and pass it to noise
        // let mut _first_message = [u8; 32 /* e */ + 32 + 16 /* encrypted s */ + 16 /* payload tag */];
        let (initiator_state, first_message) = self
            .0
            .initiate_connection(&mut rng, &prologue, remote_public_key, None)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("noise: wrong input passed {}", e),
                )
            })?;

        // write the first handshake message
        poll_fn(|context| poll_write_all(context, Pin::new(&mut socket), &first_message, 0))
            .await?;

        // flush
        poll_fn(|context| Pin::new(&mut socket).poll_flush(&mut context)).await;

        // receive the server's response (<- e, ee, se)
        let mut server_response = [0u8; 32 /* e */ + 16 /* payload tag */];
        poll_fn(|context| poll_read_exact(context, Pin::new(&mut socket), &mut server_response, 0))
            .await?;

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

    pub async fn accept<TSocket>(&self, socket: TSocket) -> io::Result<NoiseSocket<TSocket>>
    where
        TSocket: AsyncRead + AsyncWrite + Unpin,
    {
        // receives prologue as the client timestamp in seconds
        let mut prologue = [0u8; 8];
        poll_fn(|context| poll_read_exact(context, Pin::new(&mut socket), &mut prologue, 0))
            .await?;
        let client_timestamp_u64 = u64::from_be_bytes(prologue);
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
        let mut client_init_message =
            [0u8; 32 /* e */ + 32 + 16 /* encrypted s */ + 16 /* payload tag */];
        poll_fn(|context| {
            poll_read_exact(context, Pin::new(&mut socket), &mut client_init_message, 0)
        })
        .await?;

        // parse it
        let mut rng = rand::thread_rng();
        let (their_public_key, handshake_state) = self
            .0
            .parse_client_init_message(&mut rng, &prologue, &client_init_message, None)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("noise: wrong message received {}", e),
                )
            })?;

        // TODO: make sure the public key is a validator before continuing (if we're in the validator network)

        // check the timestamp is not a replay
        {
            let mut timestamps = LAST_SEEN_CLIENT_TIMESTAMPS.lock().unwrap();
            if let Some(timestamp) = timestamps.get(their_public_key) {
                // TODO: security logging the ip + blocking the ip? (mimoo)
                if timestamp == client_timestamp_u64 {
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
        let mut server_response = [0u8; 32 /* e */ + 16 /* payload tag */];
        let session = self
            .0
            .respond_to_client(&mut rng, handshake_state, None, &mut server_response)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("noise: wrong message received {}", e),
                )
            })?;
        poll_fn(|context| poll_write_all(context, Pin::new(&mut socket), &server_response, 0))
            .await?;

        // the connection succeeded, store the client timestamp for replay prevention
        {
            let mut timestamps = LAST_SEEN_CLIENT_TIMESTAMPS.lock().unwrap();
            timestamps
                .entry(their_public_key)
                .and_modify(client_timestamp_u64)
                .or_insert(client_timestamp_u64);
        }

        // finalize the connection
        Ok(NoiseSocket::new(socket, session))
    }
}

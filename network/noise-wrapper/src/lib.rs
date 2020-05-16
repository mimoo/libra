// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This crate implements wrappers around our [Noise][noise] implementation.
//! Noise is used to encrypt and authenticate connections between peers.
//! Specifically, we use the [Noise IK][ik] handshake which is a one round-trip protocol
//! (the client sends one message, then the server responds).
//! For more information about Noise and our implementation, refer to the [crypto] crate.
//!
//!
//! ```
//! ```
//!
//! [noise]: http://noiseprotocol.org/
//! [ik]: https://noiseexplorer.com/patterns/IK
//! [crypto]: ../libra_crypto/noise/index.html

pub mod handshake;
pub mod socket;
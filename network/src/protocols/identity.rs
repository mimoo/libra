// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Protocol used to exchange supported protocol information with a remote.

use crate::protocols::wire::handshake::v1::{
    HandshakeMsg, MessagingProtocolVersion, SupportedProtocols,
};
use bytes::BytesMut;
use futures::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use libra_logger::prelude::*;
use libra_types::PeerId;
use netcore::framing::{read_u16frame, write_u16frame};
use std::io;

/// The Handshake exchange protocol.
pub async fn exchange_handshake<T>(
    own_handshake: &HandshakeMsg,
    socket: &mut T,
) -> io::Result<HandshakeMsg>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // Send serialized handshake message to remote peer.
    let msg = lcs::to_bytes(own_handshake).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to serialize identity msg: {}", e),
        )
    })?;
    write_u16frame(socket, &msg).await?;
    socket.flush().await?;

    // Read handshake message from the Remote
    let mut response = BytesMut::new();
    read_u16frame(socket, &mut response).await?;
    let identity = lcs::from_bytes(&response).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse identity msg: {}", e),
        )
    })?;
    Ok(identity)
}

/// Exchange HandshakeMsg's to try negotiating a set of common supported protocols.
pub async fn perform_handshake(
    peer_id: PeerId,
    remote_handshake_msg: HandshakeMsg,
    own_handshake: &HandshakeMsg,
) -> io::Result<(MessagingProtocolVersion, SupportedProtocols)> {
    // verify well-formedness
    if !own_handshake.verify(&remote_handshake_msg) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Handshakes don't match networks own: {} received: {}",
                own_handshake, remote_handshake_msg
            ),
        ));
    }

    // find common protocols
    let intersecting_protocols = own_handshake.find_common_protocols(&remote_handshake_msg);
    intersecting_protocols.ok_or_else(|| {
        info!(
            "No matching protocols found for connection with peer: {}. Handshake received: {}",
            peer_id.short_str(),
            remote_handshake_msg
        );
        io::Error::new(io::ErrorKind::Other, "no matching messaging protocol")
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        protocols::{
            identity::exchange_handshake,
            wire::handshake::v1::{HandshakeMsg, MessagingProtocolVersion},
        },
        ProtocolId,
    };
    use futures::{executor::block_on, future::join};
    use libra_config::network_id::NetworkId;
    use libra_types::chain_id::ChainId;
    use memsocket::MemorySocket;

    fn build_test_connection() -> (MemorySocket, MemorySocket) {
        MemorySocket::new_pair()
    }

    #[test]
    fn simple_handshake() {
        let network_id = NetworkId::Validator;
        let chain_id = ChainId::test();
        let (mut outbound, mut inbound) = build_test_connection();

        // Create client and server handshake messages.
        let mut server_handshake = HandshakeMsg::new(chain_id, network_id.clone());
        server_handshake.add(
            MessagingProtocolVersion::V1,
            [
                ProtocolId::ConsensusDirectSend,
                ProtocolId::MempoolDirectSend,
            ]
            .iter()
            .into(),
        );
        let mut client_handshake = HandshakeMsg::new(chain_id, network_id);
        client_handshake.add(
            MessagingProtocolVersion::V1,
            [ProtocolId::ConsensusRpc, ProtocolId::ConsensusDirectSend]
                .iter()
                .into(),
        );

        let server_handshake_clone = server_handshake.clone();
        let client_handshake_clone = client_handshake.clone();

        let server = async move {
            let handshake = exchange_handshake(&server_handshake, &mut inbound)
                .await
                .expect("Handshake fails");

            assert_eq!(
                lcs::to_bytes(&handshake).unwrap(),
                lcs::to_bytes(&client_handshake_clone).unwrap()
            );
        };

        let client = async move {
            let handshake = exchange_handshake(&client_handshake, &mut outbound)
                .await
                .expect("Handshake fails");

            assert_eq!(
                lcs::to_bytes(&handshake).unwrap(),
                lcs::to_bytes(&server_handshake_clone).unwrap()
            );
        };

        block_on(join(server, client));
    }

    #[test]
    fn handshake_network_id_mismatch() {
        let (outbound, inbound) = MemorySocket::new_pair();

        let mut server_handshake = HandshakeMsg::new(ChainId::default(), NetworkId::Validator);
        // This is required to ensure that test doesn't get an error for a different reason
        server_handshake.add(
            MessagingProtocolVersion::V1,
            [ProtocolId::ConsensusDirectSend].iter().into(),
        );
        let mut client_handshake = server_handshake.clone();
        // Ensure client doesn't match networks
        client_handshake.network_id = NetworkId::Public;

        let server = async move {
            let remote_handshake = exchange_handshake(&ctxt.own_handshake, &mut inbound)
                .await
                .unwrap();
            perform_handshake(PeerId::random(), remote_handshake, &server_handshake)
                .await
                .unwrap_err()
        };

        let client = async move {
            let remote_handshake = exchange_handshake(&ctxt.own_handshake, &mut outbound)
                .await
                .unwrap();
            perform_handshake(PeerId::random(), remote_handshake, &client_handshake)
                .await
                .unwrap_err()
        };

        block_on(future::join(server, client));
    }
}

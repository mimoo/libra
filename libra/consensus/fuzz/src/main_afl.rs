#![feature(async_await)]

#[macro_use]
extern crate afl;

use bytes::Bytes;
use config::config::ConsensusProposerType::FixedProposer;
use consensus::chained_bft::{
    chained_bft_smr_test::SMRNode, mock_storage::MockStorage, network_tests::NetworkPlayground,
    test_utils::consensus_runtime,
};
use futures::executor::block_on;
use network::{
    interface::NetworkNotification, protocols::direct_send::Message,
    validator_network::CONSENSUS_DIRECT_SEND_PROTOCOL, ProtocolId,
};
use protobuf::Message as proto;
use rand::{rngs::StdRng, SeedableRng};
use std::{collections::HashMap, io::prelude::*, sync::Arc};
use types::{
    account_address::AccountAddress, validator_signer::ValidatorSigner,
    validator_verifier::ValidatorVerifier,
};

#[allow(missing_docs)]
fn create_corpus() {
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.executor());

    let _nodes = SMRNode::start_num_nodes(2, 2, &mut playground, FixedProposer);

    block_on(async move {
        for id in 0..100 {
            let msg = playground
                .wait_for_messages(1, NetworkPlayground::proposals_only)
                .await;
            let temp = &msg[0].1;
            let dir = env!("CARGO_MANIFEST_DIR");
            let path = format!("{}/corpcorp/{}.bin", dir, id);
            println!("saving file at {}", path);
            let mut file = std::fs::File::create(path).unwrap();
            file.write_all(&temp.write_to_bytes().unwrap()).unwrap();
        }
    });

    /*
    fuzz!(|data: &[u8]| {
        let message = Message {
            protocol: ProtocolId::from_static(CONSENSUS_DIRECT_SEND_PROTOCOL),
            mdata: Bytes::from(data),
        };

        let fuzzing_message = NetworkNotification::RecvMessage((peers[0].clone()).into(), message);

        // send fuzzing data
        block_on(async move {
            playground
                .deliver_message_fuzz(peers[0].clone(), peers[0].clone(), fuzzing_message)
                .await;
        });
    });
    */
}

fn afl() {
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.executor());

    let nodes = SMRNode::start_num_nodes(1, 1, &mut playground, FixedProposer);

    fuzz!(|data: &[u8]| {
        let message = Message {
            protocol: ProtocolId::from_static(CONSENSUS_DIRECT_SEND_PROTOCOL),
            mdata: Bytes::from(data),
        };

        let fuzzing_message =
            NetworkNotification::RecvMessage((nodes[0].author().clone()).into(), message);

        // send fuzzing data
        block_on(async move {
            playground
                .deliver_message_fuzz(
                    nodes[0].author().clone(),
                    nodes[0].author().clone(),
                    fuzzing_message,
                )
                .await;
        });
    });
}

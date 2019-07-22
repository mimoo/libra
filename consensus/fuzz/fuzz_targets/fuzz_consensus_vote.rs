#![no_main]
#![feature(async_await)]
#[macro_use]
extern crate libfuzzer_sys;
extern crate consensus;

use config::config::{NodeConfig, NodeConfigHelpers};
use consensus::chained_bft::{
    common::Author,
    event_processor_test::NodeSetup,
    liveness::pacemaker::{NewRoundEvent, NewRoundReason},
    network_tests::NetworkPlayground,
    safety::vote_msg::VoteMsg,
    test_utils::{consensus_runtime, TestPayload},
};
use futures::executor::block_on;
use lazy_static::lazy_static;
use network::proto::ConsensusMsg;
use proto_conv::FromProto;
use protobuf::Message as proto;
use std::{
    fs::{self, File},
    io::prelude::*,
    time::Duration,
};
use tokio::runtime;
use types::validator_verifier::ValidatorVerifier;

lazy_static! {
    static ref STATIC_RUNTIME: runtime::Runtime = consensus_runtime();
}

// running nothing exec/s: 26214
fuzz_target!(|data: &[u8]| {
    // TODO:
    // what would be interesting here would be to have the node propose something first
    // then we vote on it?
    let node = NodeSetup::create_node_fuzzing(STATIC_RUNTIME.executor());

    // proto parse
    let mut msg: ConsensusMsg = match protobuf::parse_from_bytes(data) {
        Ok(xx) => xx,
        Err(_) => {
            // println!("{:?}", x);
            return;
        }
    };

    // extract vote
    let vote = match msg.has_vote() {
        true => match VoteMsg::from_proto(msg.take_vote()) {
            Ok(xx) => xx,
            Err(_) => return,
        },
        false => return,
    };

    // process vote (network.rs)
    let validator = ValidatorVerifier::new_empty();
    match vote.verify(&validator) {
        Err(_) => {
            // println!("{:?}", x);
            return;
        }
        _ => (),
    }

    block_on(async move {
        // process proposal (event_process)
        node.event_processor.process_vote(vote.clone(), 0).await;
    });
});

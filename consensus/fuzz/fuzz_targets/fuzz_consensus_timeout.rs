#![no_main]
#![feature(async_await)]
#[macro_use]
extern crate libfuzzer_sys;
extern crate consensus;

use consensus::chained_bft::{
    common::Author, consensus_types::timeout_msg::TimeoutMsg, event_processor_test::NodeSetup,
    test_utils::consensus_runtime,
};
use futures::executor::block_on;
use lazy_static::lazy_static;
use network::proto::ConsensusMsg;
use proto_conv::FromProto;
use protobuf::Message as proto;
use tokio::runtime;
use types::validator_verifier::ValidatorVerifier;

lazy_static! {
    static ref STATIC_RUNTIME: runtime::Runtime = consensus_runtime();
}

fuzz_target!(|data: &[u8]| {
    //
    let node = NodeSetup::create_node_fuzzing(STATIC_RUNTIME.executor());

    // proto parse
    let mut msg: ConsensusMsg = match protobuf::parse_from_bytes(data) {
        Ok(xx) => xx,
        Err(_) => {
            // println!("{:?}", x);
            return;
        }
    };

    // extract timeout
    let timeout_msg = match msg.has_timeout() {
        true => match TimeoutMsg::from_proto(msg.take_proposal()) {
            Ok(xx) => xx,
            Err(_) => return,
        },
        false => return,
    };

    // process timeout (network.rs)
    let validator = ValidatorVerifier::new_empty();
    match timeout_msg.verify(&validator) {
        Err(_) => {
            // println!("{:?}", x);
            return;
        }
        _ => (),
    }

    block_on(async move {
        // process proposal (event_process)
        node.event_processor
            .process_timeout_msg(timeout_msg.clone(), 0)
            .await;
    });
});

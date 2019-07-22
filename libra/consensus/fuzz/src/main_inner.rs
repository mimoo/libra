#![feature(async_await)]

//#[macro_use]
//extern crate afl;

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

// proposal
fn main() {
    // fuzz
    let mut data = [0; 1000];
    let mut f = File::open("/Users/davidwg/libra/libra/consensus/proposal.hex").unwrap();
    let n = f.read(&mut data[..]).unwrap();
    let data = data[..n];

    // setup
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.executor());
    let nodes = NodeSetup::create_nodes(&mut playground, runtime.executor(), 1);
    let node = &nodes[0];

    // proto parse
    let msg: ConsensusMsg;
    match protobuf::parse_from_bytes(&data) {
        Ok(x) => msg = x,
        Err(x) => return,
    }

    // extract consensus message
    let r = if msg.has_proposal() {
        match ProposalInfo::<TestPayload, Author>::from_proto(msg.take_proposal()) {
            Ok(xx) => process_proposal(node, xx),
            Err(_) => return,
        }
    } else if msg.has_vote() {
        /*
        let vote = VoteMsg::from_proto(msg.take_vote())?;
        debug!("Received vote {:?}", vote);
        vote.verify(self.validator.as_ref()).map_err(|e| {
            security_log(SecurityEvent::InvalidConsensusVote)
                .error(&e)
                .data(&vote)
                .log();
            e
        })?;
        */
        //process_vote(&mut msg).await
    } else if msg.has_new_round() {
        /*
        let new_round = NewRoundMsg::from_proto(msg.take_new_round())?;
        new_round.verify(self.validator.as_ref()).map_err(|e| {
            security_log(SecurityEvent::InvalidConsensusRound)
                .error(&e)
                .data(&new_round)
                .log();
            e
        })?;
        */
        return;
        //process_new_round(&mut msg).await
    } else {
        return;
    }
 
}

/*
 - node spin up event stuff in network, grpc
 0.
 - chained_bft/network.rs
    1. NetworkTask::run() 
        - process every consensus message
    2.process_proposal<'a>(&'a mut self, msg: &'a mut ConsensusMsg) -> failure::Result<()> 

 - chained_bft_smr.rs
    process_proposals()
        - chained_bft/event_processor.rs
        3. process_proposal(&self,proposal: ProposalInfo<T, P>)  -> ProcessProposalResult
            it also sends it to proposal_candidates_sender
 - chained_bft_smrs.rs
    process_winning_proposals()
        receives through proposal_winners_receiver
        - chained_bft/event_processor.rs
        4. process_winning_proposal(&self, proposal: ProposalInfo<T, P>)
*/

fn process_proposal(node: &NodeSetup, proposal: ) {
    proposal.verify(node.validator.as_ref()).map_err(|e| {
        security_log(SecurityEvent::InvalidConsensusProposal)
            .error(&e)
            .data(&proposal)
            .log();
        e
    })?;
    block_on(async move {
        node.event_processor
            .process_proposal(msg)
            .await;
    }); // returns () or needfetch
    block_on(async move {
        node.event_processor
            .process_winning_proposal(msg)
            .await;
    });
}

/*
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
*/

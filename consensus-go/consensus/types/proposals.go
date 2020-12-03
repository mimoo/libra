package types

import "crypto/ed25519"

// BlockProposal is a proposed a block of transactions (by an author).
type BlockProposal struct {
	epoch          uint64
	round          uint64
	timestampUsecs uint64
	quorumCert     QuorumCert
	payload        []SignedTransaction
	author         Address
	signature      [ed25519.SignatureSize]byte
}

// NilProposal represents an empty proposal in a round that timed out.
type NilProposal struct {
	epoch          uint64
	round          uint64
	timestampUsecs uint64
	quorumCert     QuorumCert
}

// GenesisProposal is a fake proposal, generated automatically at the start of every new epoch.
type GenesisProposal struct {
	epoch          uint64
	round          uint64
	timestampUsecs uint64
	quorumCert     QuorumCert
}

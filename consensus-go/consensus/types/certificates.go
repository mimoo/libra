package types

import "crypto/ed25519"

// TimeoutCertificate represents 2f+1 timeouts on an epoch and round.
type TimeoutCertificate struct {
	epoch      uint64
	round      uint64
	signatures map[Address][ed25519.SignatureSize]byte
}

// QuorumCert represents 2f+1 votes on a proposed block (and its parent).
type QuorumCert struct {
	proposed BlockInfo
	parent   BlockInfo
}

// BlockInfo summarizes a block observed, including the ledger state after execution of the block, and potentially a new EpochState in case the block triggered a reconfiguration.
type BlockInfo struct {
	epoch           uint64
	round           uint64
	id              [32]byte
	executedStateID [32]byte
	version         uint64
	timestampUsecs  uint64
	nextEpochState  *EpochState
}

// EpochState represents the validator state for an epoch.
type EpochState struct {
	epoch                  uint64
	addressToValidatorInfo map[Address][ed25519.PublicKeySize]byte
}

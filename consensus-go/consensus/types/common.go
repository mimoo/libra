package types

import "crypto/ed25519"

// Address represents an account in Diem.
type Address = [32]byte

type SignedTransaction struct {
	transaction Transaction
	signatures  map[[ed25519.PublicKeySize]byte][ed25519.SignatureSize]byte
}

type TransactionScript struct {
	sender                  Address
	sequenceNumber          uint64
	maxGasAmount            uint64
	gasUnitPrice            uint64
	gasCurrencyCode         string
	expirationTimestampSecs uint64
	chainID                 uint8

	code   []byte
	tyArgs []TypeTag
	args   []TransactionArgument
}

type TypeTag uint32

const (
	Bool TypeTag = iota
	U8
	U64
	U128
	Address
	Signer
	Vector
	Struct
)

type TransactionArgument uint32

const (
	U8 TransactionArgument = iota
	U64
	U128
	Address
	U8Vector
	Bool
)

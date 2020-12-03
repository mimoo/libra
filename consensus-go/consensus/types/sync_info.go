package types

type SyncInfo struct {
	highestQuorumCert  QuorumCert
	highestCommitCert  *QuorumCert
	highestTimeoutCert *TimeoutCertificate
}

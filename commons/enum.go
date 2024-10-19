package commons

const (
	SendPublicKey = iota
	SwitchToSymmetricKey
	ClientSendHost
	GetSigningServers
	GetTrustedDomains
	InitiateForwarding
)

const (
	XChaCha20Poly1305 = iota
)

const (
	BitLimit24 = 16_777_215
	BitLimit16 = 65535
)

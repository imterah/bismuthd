// Enums used internally

package commons

// Commands
const (
	// SendPublicKey: Sending public key back and forth
	SendPublicKey = iota
	// SwitchToSymmetricKey: Sent by the client along with the symmetric key that is going to be used
	SwitchToSymmetricKey
	// ClientSendHost: Currently unimplemented.
	// Client sends what host they are connecting to.
	ClientSendHost
	// GetSigningServers: Currently unimplemented.
	// Gets the signing servers trusting/signing the current server.
	GetSigningServers
	// GetTrustedDomains: Currently unimplemented.
	// Gets the domains that are supported by this certificate (should be cross-checked)
	GetTrustedDomains
	// InitiateForwarding: Starts forwarding traffic over this protocol.
	InitiateForwarding
)

// Encryption algorithms
const (
	// Default and only encryption algorithm
	XChaCha20Poly1305 = iota
)

// Unsigned integer limits
const (
	BitLimit24 = 16_777_215
	BitLimit16 = 65535
)

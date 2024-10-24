// Enums used internally

package commons

// Core Protocol Commands
const (
	// Sending public key back and forth
	SendPublicKey = iota
	// Sent by the client along with the symmetric key that is going to be used
	SwitchToSymmetricKey
	// Client sends what host they are connecting to.
	ClientSendHost
	// Gets the signing servers trusting/signing the current server.
	GetSigningServers
	// Gets the domains that are supported by this certificate (should be cross-checked)
	GetTrustedDomains
	// Starts forwarding traffic over this protocol.
	InitiateForwarding
)

// Validation API Commands
const (
	// Checks if the domains are valid for a specified key
	AreDomainsValidForKey = iota
	// Validate a server and keys
	ValidateKey
	// Status codes
	Success
	Failure
	InternalError
)

// Encryption Algorithms
const (
	// Default and only encryption algorithm
	XChaCha20Poly1305 = iota
)

// Unsigned Integer Limits
const (
	BitLimit24 = 16_777_215
	BitLimit16 = 65535
)

package server

import (
	"net"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Bismuth Server
type BismuthServer struct {
	// Public key to use for transmission
	PublicKey *crypto.Key
	// Private key to use for transmission
	PrivateKey *crypto.Key

	// GopenPGP instance
	pgp *crypto.PGPHandle

	// Algorithm to use for encryption (currently XChaCha20Poly1305 is the only option)
	SymmetricEncryptionAlgorithm int
	// Servers that are signing this server. If none, this server becomes self-signed
	// in the clients eyes.
	SigningServers []string
	// Domains that the certificate is authorized to use. This will be checked by the
	// signing servers.
	TrustedDomains []string

	// Called after a successful handshake & connection.
	HandleConnection func(conn net.Conn, metadata *ClientMetadata) error
}

// Metadata from the client that may be helpful for the server to have.
type ClientMetadata struct {
	// Client's public key
	ClientPublicKey *crypto.Key
}

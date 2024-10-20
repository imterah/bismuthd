package client

import (
	"net"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Checks to see if a certificate is trusted in the client cache.
//
//   - `host`: The host of the server.
//   - `certificateFingerprint`: A fingerprint of the servers key.
//   - `isSelfSigned`: If true, the certificate is either actually self-signed, or
//     verification is dsabled (CheckIfCertificatesAreSigned in BismuthClient is false)
//   - `isTrustworthy`: If true, the certificate is signed by 51% of peers.
type CertCheckCallback func(host, certificateFingerprint string, isSelfSigned, isTrustworthy bool) bool

// Connects to a server using a provided method, with host being the host:
//
// OwnConnMethodCallback("google.com:80")
type OwnConnMethodCallback func(address string) (net.Conn, error)

// Bismuth Client
type BismuthClient struct {
	// GOpenPGP public key
	PublicKey *crypto.Key
	// GOpenPGP private key
	PrivateKey *crypto.Key

	// Check if the certificates are signed if enabled.
	//
	// If true, "cross-verifies" the server to make sure the certificates are signed.
	//
	// If false, all certificates will be reported as being self signed because we can't
	// really prove otherwise.
	CheckIfCertificatesAreSigned bool
	// Checks to see if a certificate is trusted in the client cache.
	// See CertCheckCallback for more typing information.
	CertificateSignChecker CertCheckCallback

	// Connects to a server (used for CheckIfCertificatesAreSigned if enabled/set to true).
	ConnectToServer OwnConnMethodCallback

	// GopenPGP instance
	pgp *crypto.PGPHandle
}

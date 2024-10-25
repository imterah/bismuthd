package client

import (
	"net"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Bismuth Client
type BismuthClient struct {
	// GOpenPGP public key for the client
	PublicKey *crypto.Key
	// GOpenPGP private key for the client
	PrivateKey *crypto.Key

	// Check if the certificates are signed if enabled.
	//
	// If true, "cross-verifies" the server to make sure the certificates are signed.
	//
	// If false, all certificates will be reported as being self signed because we can't
	// really prove otherwise.
	CheckIfCertificatesAreSigned bool

	// Checks to see if a certificate is trusted in the client cache.
	//
	//   - `host`: The host of the server.
	//   - `certificateFingerprint`: A fingerprint of the servers key.
	//   - `isSelfSigned`: If true, the certificate is either actually self-signed, or
	//     verification is dsabled (CheckIfCertificatesAreSigned in BismuthClient is false)
	//
	// This function will only be called if client.CheckIfCertificatesAreSigned is true.
	//
	// Example usage inside the Bismuth client source:
	//     client.CertificateSignChecker("example.com:9090", "6c5eaff6f5c65e65e6f6ce6fc", false, true)
	CertificateSignChecker func(host, certificateFingerprint string, isSelfSigned bool) bool

	// If any certificates are false in the certificate cache, and the client has determined that
	// they may need to be added, this function will get called.
	//
	// All of the certificates that will be called by this function in arguments are ones that
	// client.CertificateSignChecker has reported to be untrustworthy, but not all untrustworthy
	// certificates will be reported, as they can be trusted by future nodes that you have already
	// trusted.
	//
	// This function will only be called if client.CheckIfCertificatesAreSigned is true.
	AddCertificatesToSignCache func(certificates []*BismuthCertificates)

	// Connects to a server.
	// This function will only be called if client.CheckIfCertificatesAreSigned is true.
	//
	// Example usage in the client source:
	//     client.ConnectToServer("google.com:80")
	ConnectToServer func(address string) (net.Conn, error)

	// GopenPGP instance
	pgp *crypto.PGPHandle
}

// Sign result data for the node
type BismuthSignResultData struct {
	// Future node pointers in the tree
	ChildNodes []*BismuthSignResultData

	// If true, the server is already trusting this node
	IsTrusting bool
}

type BismuthSignResults struct {
	// Overall trust score calculated
	OverallTrustScore int
	// Parent node in tree for sign results
	Node *BismuthSignResultData

	// GopenPGP public key
	ServerPublicKey *crypto.Key
}

type BismuthCertificates struct {
	// The host of the server
	Host string
	// A fingerprint of the servers key
	CertificateFingerprint string
	// Certificate UserID
	CertificateUsername string
	CertificateMail     string

	// If true, the certificate is self signed
	IsSelfSigned bool

	// If true, the client should not prompt the user, and automatically
	// add the certificate instead.
	ShouldAutomaticallyAdd bool
}

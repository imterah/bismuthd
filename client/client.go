package client

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net"

	core "git.greysoh.dev/imterah/bismuthd/commons"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

func (bismuth BismuthClient) encryptMessage(aead cipher.AEAD, msg []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

	if _, err := rand.Read(nonce); err != nil {
		return []byte{}, err
	}

	encryptedMsg := aead.Seal(nonce, nonce, msg, nil)
	return encryptedMsg, nil
}

func (bismuth BismuthClient) decryptMessage(aead cipher.AEAD, encMsg []byte) ([]byte, error) {
	if len(encMsg) < aead.NonceSize() {
		return []byte{}, fmt.Errorf("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := encMsg[:aead.NonceSize()], encMsg[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	decryptedData, err := aead.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return []byte{}, err
	}

	return decryptedData, nil
}

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

// Initializes the client. Should be done automatically if you call New()
//
// If you don't call client.New(), you *MUST* call this function before running bismuth.Conn().
func (bismuth *BismuthClient) InitializeClient() error {
	if bismuth.pgp == nil {
		bismuth.pgp = crypto.PGP()
	}

	if bismuth.CertificateSignChecker == nil {
		bismuth.CertificateSignChecker = func(host, certificateFingerprint string, isSelfSigned, isTrustworthy bool) bool {
			fmt.Println("WARNING: Using stub CertificateSignChecker. Returing true and ignoring arguments")
			return true
		}
	}

	if bismuth.ConnectToServer == nil {
		bismuth.ConnectToServer = func(address string) (net.Conn, error) {
			return net.Dial("tcp", address)
		}
	}

	return nil
}

// Connects to a Bismuth server. This wraps an existing net.Conn interface.
// The returned net.Conn is the server, but over bismuth.
func (bismuth BismuthClient) Conn(conn net.Conn) (net.Conn, error) {
	// Yes, I'm aware defer exists. It won't work if I use it in this context. I'll shank anyone that complains
	// Exchange our public keys first

	ownKey, err := bismuth.PublicKey.GetPublicKey()

	if err != nil {
		conn.Close()
		return nil, err
	}

	pubKeyLengthBytes := make([]byte, 3)
	pubKeyLength := uint32(len(ownKey))
	core.Int32ToInt24(pubKeyLengthBytes, pubKeyLength)

	conn.Write([]byte{core.SendPublicKey})
	conn.Write(pubKeyLengthBytes)
	conn.Write(ownKey)

	messageMode := make([]byte, 1)

	if _, err = conn.Read(messageMode); err != nil {
		conn.Close()
		return nil, err
	}

	if messageMode[0] != core.SendPublicKey {
		conn.Close()
		return nil, fmt.Errorf("server failed to return its public key")
	}

	if _, err = conn.Read(pubKeyLengthBytes); err != nil {
		conn.Close()
		return nil, err
	}

	pubKeyLength = core.Int24ToInt32(pubKeyLengthBytes)
	pubKeyBytes := make([]byte, pubKeyLength)

	if _, err = conn.Read(pubKeyBytes); err != nil {
		conn.Close()
		return nil, err
	}

	if _, err = crypto.NewKey(pubKeyBytes); err != nil {
		conn.Close()
		return nil, err
	}

	// Then exchange the symmetric key

	conn.Write([]byte{core.SwitchToSymmetricKey})

	if _, err = conn.Read(messageMode); err != nil {
		conn.Close()
		return nil, err
	}

	if messageMode[0] != core.SwitchToSymmetricKey {
		conn.Close()
		return nil, fmt.Errorf("server failed to return symmetric key")
	}

	encryptedSymmKeyLengthInBytes := make([]byte, 3)

	if _, err = conn.Read(encryptedSymmKeyLengthInBytes); err != nil {
		conn.Close()
		return nil, err
	}

	encryptedSymmKeyLength := core.Int24ToInt32(encryptedSymmKeyLengthInBytes)
	encryptedSymmKey := make([]byte, encryptedSymmKeyLength)

	if _, err = conn.Read(encryptedSymmKey); err != nil {
		conn.Close()
		return nil, err
	}

	decHandleForSymmKey, err := bismuth.pgp.Decryption().DecryptionKey(bismuth.PrivateKey).New()

	if err != nil {
		return nil, err
	}

	decryptedSymmKey, err := decHandleForSymmKey.Decrypt(encryptedSymmKey, crypto.Bytes)

	if err != nil {
		return nil, err
	}

	symmKeyInfo := decryptedSymmKey.Bytes()

	if symmKeyInfo[0] != core.XChaCha20Poly1305 {
		conn.Close()
		return nil, fmt.Errorf("unsupported encryption method recieved")
	}

	symmKey := symmKeyInfo[1 : chacha20poly1305.KeySize+1]
	aead, err := chacha20poly1305.NewX(symmKey)

	// Start proxying

	startForwardingPacket := []byte{
		core.InitiateForwarding,
	}

	encryptedForwardPacket, err := bismuth.encryptMessage(aead, startForwardingPacket)

	if err != nil {
		conn.Close()
		return nil, err
	}

	encryptedForwardPacketPacketSize := make([]byte, 3)

	core.Int32ToInt24(encryptedForwardPacketPacketSize, uint32(len(encryptedForwardPacket)))

	conn.Write(encryptedForwardPacketPacketSize)
	conn.Write(encryptedForwardPacket)

	_, err = bismuth.decryptMessage(aead, encryptedForwardPacket)

	bmConn := core.BismuthConn{
		Aead:       aead,
		PassedConn: conn,
		MaxBufSize: core.ConnStandardMaxBufSize,
	}

	bmConn.DoInitSteps()

	return core.BismuthConnWrapped{
		Bismuth: &bmConn,
	}, nil
}

// Creates a new BismuthClient.
//
// Both `pubKey` and `privKey` are armored PGP public and private keys respectively.
func New(pubKey string, privKey string) (*BismuthClient, error) {
	publicKey, err := crypto.NewKeyFromArmored(pubKey)

	if err != nil {
		return nil, err
	}

	privateKey, err := crypto.NewKeyFromArmored(privKey)

	if err != nil {
		return nil, err
	}

	bismuth := BismuthClient{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	err = bismuth.InitializeClient()

	if err != nil {
		return nil, err
	}

	return &bismuth, nil
}

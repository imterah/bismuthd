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

// Bismuth Client
type BismuthClient struct {
	// GOpenPGP public key
	PublicKey *crypto.Key
	// GOpenPGP private key
	PrivateKey *crypto.Key

	pgp *crypto.PGPHandle
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

	pgp := crypto.PGP()

	bismuth := BismuthClient{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		pgp:        pgp,
	}

	return &bismuth, nil
}

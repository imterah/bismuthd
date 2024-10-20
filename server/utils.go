package server

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

func (bismuth BismuthServer) encryptMessage(aead cipher.AEAD, msg []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

	if _, err := rand.Read(nonce); err != nil {
		return []byte{}, err
	}

	encryptedMsg := aead.Seal(nonce, nonce, msg, nil)
	return encryptedMsg, nil
}

func (bismuth BismuthServer) decryptMessage(aead cipher.AEAD, encMsg []byte) ([]byte, error) {
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

// Initializes a Bismuth server.
//
// Both `pubKey` and `privKey` are armored PGP public and private keys respectively.
func NewBismuthServer(pubKey string, privKey string, signServers []string, encryptionAlgo int, connHandler func(conn net.Conn) error) (*BismuthServer, error) {
	publicKey, err := crypto.NewKeyFromArmored(pubKey)

	if err != nil {
		return nil, err
	}

	privateKey, err := crypto.NewKeyFromArmored(privKey)

	if err != nil {
		return nil, err
	}

	pgp := crypto.PGP()

	bismuth := BismuthServer{
		PublicKey:                    publicKey,
		PrivateKey:                   privateKey,
		HandleConnection:             connHandler,
		SigningServers:               signServers,
		SymmetricEncryptionAlgorithm: encryptionAlgo,
		pgp:                          pgp,
	}

	return &bismuth, nil
}

package client

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

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

package bismuthd_test

import (
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

// Creates an armored GPG keyring
// Argument order is public key, then private key
func CreateKeyring(name, email string) (string, string, error) {
	pgp := crypto.PGPWithProfile(profile.RFC9580())

	privateKey, err := pgp.KeyGeneration().
		AddUserId(name, email).
		New().
		GenerateKey()

	if err != nil {
		return "", "", err
	}

	publicKey, err := privateKey.ToPublic()

	if err != nil {
		return "", "", err
	}

	privateKeyArmored, err := privateKey.Armor()

	if err != nil {
		return "", "", err
	}

	publicKeyArmored, err := publicKey.Armor()

	if err != nil {
		return "", "", err
	}

	return publicKeyArmored, privateKeyArmored, nil
}

package server

import (
	"fmt"
	"net"

	core "git.greysoh.dev/imterah/bismuthd/commons"

	"crypto/cipher"
	"crypto/rand"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"golang.org/x/crypto/chacha20poly1305"
)

type BismuthServer struct {
	PublicKey  *crypto.Key
	PrivateKey *crypto.Key

	pgp *crypto.PGPHandle

	SymmetricEncryptionAlgorithm int

	SigningServers []string

	// This is what's called after a successful handshake & connection.
	HandleConnection func(conn net.Conn) error
}

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

// This is what's called to handle a connnection for Bismuth.
func (bismuth BismuthServer) HandleProxy(conn net.Conn) error {
	serverState := "keyHandshake"

	var clientPublicKey *crypto.Key
	var aead cipher.AEAD

	for {
		if serverState == "keyHandshake" {
			dataModeByteArr := make([]byte, 1)
			_, err := conn.Read(dataModeByteArr)

			dataMode := dataModeByteArr[0]

			if err != nil {
				conn.Close()
				return err
			}

			if dataMode == core.SendPublicKey {
				pubKeyLengthBytes := make([]byte, 3)
				_, err := conn.Read(pubKeyLengthBytes)

				if err != nil {
					conn.Close()
					return err
				}

				pubKeyLength := core.Int24ToInt32(pubKeyLengthBytes)

				publicKey := make([]byte, pubKeyLength)
				_, err = conn.Read(publicKey)

				pubKey := publicKey[:]

				// Attempt to parse the public key
				clientPublicKey, err = crypto.NewKey(pubKey)

				if err != nil {
					conn.Close()
					return err
				}

				// Now, we send our key
				pubKey, err = bismuth.PublicKey.GetPublicKey()

				if err != nil {
					conn.Close()
					return err
				}

				pubKeyLength = uint32(len(pubKey))
				core.Int32ToInt24(pubKeyLengthBytes, pubKeyLength)

				conn.Write([]byte{core.SendPublicKey})
				conn.Write(pubKeyLengthBytes)
				conn.Write([]byte(pubKey))

				serverState = "symmHandshake"
			}
		} else if serverState == "symmHandshake" {
			dataModeByteArr := make([]byte, 1)
			_, err := conn.Read(dataModeByteArr)

			dataMode := dataModeByteArr[0]

			if err != nil {
				conn.Close()
				return err
			}

			if dataMode == core.SwitchToSymmetricKey {
				// TODO: Make this not hard-coded
				symmetricKey := make([]byte, chacha20poly1305.KeySize)

				encryptionData := []byte{
					byte(bismuth.SymmetricEncryptionAlgorithm),
				}

				if _, err := rand.Read(symmetricKey); err != nil {
					conn.Close()
					return err
				}

				encryptionData = append(encryptionData, symmetricKey...)

				encHandle, err := bismuth.pgp.Encryption().Recipient(clientPublicKey).New()

				if err != nil {
					conn.Close()
					return err
				}

				pgpMessage, err := encHandle.Encrypt(encryptionData)

				if err != nil {
					conn.Close()
					return err
				}

				encryptedMessage := pgpMessage.Bytes()
				gpgMessageLengthBytes := make([]byte, 3)

				core.Int32ToInt24(gpgMessageLengthBytes, uint32(len(encryptedMessage)))

				conn.Write([]byte{core.SwitchToSymmetricKey})
				conn.Write(gpgMessageLengthBytes)
				conn.Write(encryptedMessage)

				aead, err = chacha20poly1305.NewX(symmetricKey)

				if err != nil {
					conn.Close()
					return err
				}

				serverState = "APITransmit"
			}
		} else if serverState == "APITransmit" {
			packetSizeByteArr := make([]byte, 3)

			if _, err := conn.Read(packetSizeByteArr); err != nil {
				conn.Close()
				return err
			}

			packetSize := core.Int24ToInt32(packetSizeByteArr)
			encryptedPacket := make([]byte, packetSize)

			packetSizeInt := int(packetSize)

			totalPositionRead := 0

			for packetSizeInt != totalPositionRead {
				currentPosition, err := conn.Read(encryptedPacket[totalPositionRead:packetSizeInt])
				totalPositionRead += currentPosition

				if err != nil {
					conn.Close()
					return err
				}
			}

			packet, err := bismuth.decryptMessage(aead, encryptedPacket)

			if err != nil {
				conn.Close()
				return err
			}

			if packet[0] == core.InitiateForwarding {
				bmConn := core.BismuthConn{
					Aead:       aead,
					PassedConn: conn,
					MaxBufSize: core.ConnStandardMaxBufSize,
				}

				bmConn.DoInitSteps()

				err := bismuth.HandleConnection(core.BismuthConnWrapped{
					Bismuth: &bmConn,
				})

				return err
			}
		}
	}
}

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

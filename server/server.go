package server

import (
	"net"

	core "git.greysoh.dev/imterah/bismuthd/commons"

	"crypto/cipher"
	"crypto/rand"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"golang.org/x/crypto/chacha20poly1305"
)

// Called to handle a connnection for Bismuth. The conn argument is the client you'd like to handle
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

			switch packet[0] {
			case core.GetSigningServers:
				totalPacketContents := make([]byte, 1)
				totalPacketContents[0] = core.GetSigningServers

				for index, signServer := range bismuth.SigningServers {
					totalPacketContents = append(totalPacketContents, []byte(signServer)...)

					if index+1 != len(bismuth.SigningServers) {
						totalPacketContents = append(totalPacketContents, '\n')
					}
				}

				encryptedPacket, err := bismuth.encryptMessage(aead, totalPacketContents)

				if err != nil {
					return err
				}

				encryptedPacketLength := make([]byte, 3)
				core.Int32ToInt24(encryptedPacketLength, uint32(len(encryptedPacket)))

				conn.Write(encryptedPacketLength)
				conn.Write(encryptedPacket)
			case core.GetTrustedDomains:
				totalPacketContents := make([]byte, 1)
				totalPacketContents[0] = core.GetTrustedDomains

				for index, trustedDomain := range bismuth.TrustedDomains {
					totalPacketContents = append(totalPacketContents, []byte(trustedDomain)...)

					if index+1 != len(bismuth.TrustedDomains) {
						totalPacketContents = append(totalPacketContents, '\n')
					}
				}

				encryptedPacket, err := bismuth.encryptMessage(aead, totalPacketContents)

				if err != nil {
					return err
				}

				encryptedPacketLength := make([]byte, 3)
				core.Int32ToInt24(encryptedPacketLength, uint32(len(encryptedPacket)))

				conn.Write(encryptedPacketLength)
				conn.Write(encryptedPacket)
			case core.InitiateForwarding:
				bmConn := core.BismuthConn{
					Aead:       aead,
					PassedConn: conn,
					MaxBufSize: core.ConnStandardMaxBufSize,
				}

				bmConn.DoInitSteps()

				metadata := ClientMetadata{
					ClientPublicKey: clientPublicKey,
				}

				err := bismuth.HandleConnection(core.BismuthConnWrapped{
					Bismuth: &bmConn,
				}, &metadata)

				return err
			}
		}
	}
}

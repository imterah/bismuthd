package signingserver

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	core "git.greysoh.dev/imterah/bismuthd/commons"
	"git.greysoh.dev/imterah/bismuthd/server"
)

func (signServer *BismuthSigningServer) InitializeServer() error {
	if signServer.AddVerifyHandler == nil {
		fmt.Println("WARN: You are using the default AddVerifyHandler in SignServer! This is a bad idea. Please write your own implementation!")

		signServer.AddVerifyHandler = func(serverAddr string, serverKeyFingerprint string, serverDomainList []string, additionalClientProvidedInfo string) (bool, error) {
			domainListHash := sha256.Sum256([]byte(strings.Join(serverDomainList, ":")))

			signServer.builtInVerifyMapStore[serverAddr+".fingerprint"] = serverKeyFingerprint
			signServer.builtInVerifyMapStore[serverAddr+".domainListHash"] = hex.EncodeToString(domainListHash[:])

			return true, nil
		}
	}

	if signServer.VerifyServerHandler == nil {
		fmt.Println("WARN: You are using the default VerifyServerHandler in SignServer! This is a bad idea. Please write your own implementation!")

		signServer.VerifyServerHandler = func(serverAddr string, serverKeyFingerprint string, serverDomainList []string) (bool, error) {
			domainListHash := sha256.Sum256([]byte(strings.Join(serverDomainList, ":")))
			domainListHashHex := hex.EncodeToString(domainListHash[:])

			if storedKeyFingerprint, ok := signServer.builtInVerifyMapStore[serverAddr+".fingerprint"]; ok {
				if storedKeyFingerprint != serverKeyFingerprint {
					return false, nil
				}
			} else {
				return false, nil
			}

			if storedDomainListHashHex, ok := signServer.builtInVerifyMapStore[serverAddr+".domainListHash"]; ok {
				if storedDomainListHashHex != domainListHashHex {
					return false, nil
				}
			} else {
				return false, nil
			}

			return true, nil
		}
	}

	if signServer.builtInVerifyMapStore == nil {
		signServer.builtInVerifyMapStore = map[string]string{}
	}

	signServer.BismuthServer.HandleConnection = signServer.connHandler
	return nil
}

func (signServer *BismuthSigningServer) connHandler(conn net.Conn, metadata *server.ClientMetadata) error {
	defer conn.Close()
	requestType := make([]byte, 1)

	hostAndIP := conn.RemoteAddr().String()
	hostAndIPColonIndex := strings.Index(hostAndIP, ":")

	if hostAndIPColonIndex == -1 {
		return fmt.Errorf("failed to get colon in remote address")
	}

	host := hostAndIP[:hostAndIPColonIndex]
	clientKeyFingerprint := metadata.ClientPublicKey.GetFingerprint()

	for {
		if _, err := conn.Read(requestType); err != nil {
			return err
		}

		if requestType[0] == core.AreDomainsValidForKey {
			// This is probably a bit too big, but I'd like to air on the side of caution here...
			keyFingerprintLength := make([]byte, 2)

			if _, err := conn.Read(keyFingerprintLength); err != nil {
				return err
			}

			keyFingerprintBytes := make([]byte, binary.BigEndian.Uint16(keyFingerprintLength))

			if _, err := conn.Read(keyFingerprintBytes); err != nil {
				return err
			}

			keyFingerprint := hex.EncodeToString(keyFingerprintBytes)
			serverDomainListLength := make([]byte, 2)

			if _, err := conn.Read(serverDomainListLength); err != nil {
				return err
			}

			serverDomainListBytes := make([]byte, binary.BigEndian.Uint16(serverDomainListLength))

			if _, err := conn.Read(serverDomainListBytes); err != nil {
				return err
			}

			serverDomainList := strings.Split(string(serverDomainListBytes), "\n")

			// We can't trust anything if they aren't advertising any domains/IPs
			if len(serverDomainList) == 0 {
				requestResponse := make([]byte, 1)
				requestResponse[0] = core.Failure

				conn.Write(requestResponse)
				continue
			}

			isVerified, err := signServer.VerifyServerHandler(host, keyFingerprint, serverDomainList)

			if err != nil {
				requestResponse := make([]byte, 1)
				requestResponse[0] = core.InternalError

				conn.Write(requestResponse)

				return err
			}

			if isVerified {
				requestResponse := make([]byte, 1)
				requestResponse[0] = core.Success

				conn.Write(requestResponse)
			} else {
				requestResponse := make([]byte, 1)
				requestResponse[0] = core.Failure

				conn.Write(requestResponse)
			}
		} else if requestType[0] == core.ValidateKey {
			// This is probably a bit too big, but I'd like to air on the side of caution here...
			serverDomainListLength := make([]byte, 2)

			if _, err := conn.Read(serverDomainListLength); err != nil {
				return err
			}

			serverDomainListBytes := make([]byte, binary.BigEndian.Uint16(serverDomainListLength))

			if _, err := conn.Read(serverDomainListBytes); err != nil {
				return err
			}

			serverDomainList := strings.Split(string(serverDomainListBytes), "\n")

			additionalArgumentsLength := make([]byte, 2)
			var additionalArgumentsSize uint16

			if _, err := conn.Read(additionalArgumentsLength); err != nil {
				return err
			}

			additionalArgumentsSize = binary.BigEndian.Uint16(additionalArgumentsLength)
			additionalArguments := ""

			if additionalArgumentsSize != 0 {
				additionalArgumentsBytes := make([]byte, additionalArgumentsSize)

				if _, err := conn.Read(additionalArgumentsBytes); err != nil {
					return err
				}

				additionalArguments = string(additionalArgumentsBytes)
			}

			isAddedToTrust, err := signServer.AddVerifyHandler(host, clientKeyFingerprint, serverDomainList, additionalArguments)

			if err != nil {
				return err
			}

			if isAddedToTrust {
				requestResponse := make([]byte, 1)
				requestResponse[0] = core.Success

				conn.Write(requestResponse)
			} else {
				requestResponse := make([]byte, 1)
				requestResponse[0] = core.Failure

				conn.Write(requestResponse)
			}
		}
	}
}

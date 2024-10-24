package signingclient

import (
	"encoding/binary"
	"net"
	"strings"

	core "git.greysoh.dev/imterah/bismuthd/commons"
)

func IsDomainTrusted(conn net.Conn, keyFingerprint []byte, domainList []string) (bool, error) {
	domainListAsString := strings.Join(domainList, "\n")

	keyFingerprintSize := len(keyFingerprint)
	domainListSize := len(domainListAsString)

	domainTrustedCommand := make([]byte, 1+2+2+keyFingerprintSize+domainListSize)

	domainTrustedCommand[0] = core.AreDomainsValidForKey
	currentOffset := 1

	binary.BigEndian.PutUint16(domainTrustedCommand[currentOffset:currentOffset+2], uint16(keyFingerprintSize))
	copy(domainTrustedCommand[2+currentOffset:2+currentOffset+keyFingerprintSize], keyFingerprint)

	currentOffset += 2 + keyFingerprintSize

	binary.BigEndian.PutUint16(domainTrustedCommand[currentOffset:currentOffset+2], uint16(domainListSize))
	copy(domainTrustedCommand[2+currentOffset:2+currentOffset+domainListSize], []byte(domainListAsString))

	conn.Write(domainTrustedCommand)

	requestResponse := make([]byte, 1)

	if _, err := conn.Read(requestResponse); err != nil {
		return false, err
	}

	return requestResponse[0] == core.Success, nil
}

func RequestDomainToBeTrusted(conn net.Conn, domainList []string, additionalInformation string) (bool, error) {
	domainListAsString := strings.Join(domainList, "\n")

	domainListSize := len(domainListAsString)
	additionalInfoSize := len(additionalInformation)

	requestDomainTrust := make([]byte, 1+2+2+domainListSize+additionalInfoSize)

	requestDomainTrust[0] = core.ValidateKey
	currentOffset := 1

	binary.BigEndian.PutUint16(requestDomainTrust[currentOffset:currentOffset+2], uint16(domainListSize))
	copy(requestDomainTrust[2+currentOffset:2+currentOffset+domainListSize], []byte(domainListAsString))

	currentOffset += 2 + domainListSize

	binary.BigEndian.PutUint16(requestDomainTrust[currentOffset:currentOffset+2], uint16(additionalInfoSize))
	copy(requestDomainTrust[2:currentOffset:2+currentOffset+additionalInfoSize], []byte(additionalInformation))

	conn.Write(requestDomainTrust)

	requestResponse := make([]byte, 1)

	if _, err := conn.Read(requestResponse); err != nil {
		return false, err
	}

	return requestResponse[0] == core.Success, nil
}

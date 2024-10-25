package client

import (
	"fmt"
	"net"
	"strings"

	core "git.greysoh.dev/imterah/bismuthd/commons"
	"git.greysoh.dev/imterah/bismuthd/signingclient"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

func computeNodes(children []*BismuthSignResultData) (int, int) {
	totalServerCount := 0
	passedServerCount := 0

	for _, child := range children {
		totalServerCount += 1

		if child.IsTrusting {
			passedServerCount += 1
		}

		if len(child.ChildNodes) != 0 {
			recievedTotalCount, recievedPassedCount := computeNodes(child.ChildNodes)

			totalServerCount += recievedTotalCount
			passedServerCount += recievedPassedCount
		}
	}

	return totalServerCount, passedServerCount
}

// Initializes the client. Should be done automatically if you call New()
//
// If you don't call client.New(), you *MUST* call this function before running bismuth.Conn().
func (bismuth *BismuthClient) InitializeClient() error {
	if bismuth.pgp == nil {
		bismuth.pgp = crypto.PGP()
	}

	if bismuth.CertificateSignChecker == nil {
		bismuth.CertificateSignChecker = func(host, certificateFingerprint string, isSelfSigned bool) bool {
			fmt.Println("WARNING: Using stub CertificateSignChecker. Returing true and ignoring arguments")
			return true
		}
	}

	if bismuth.AddCertificatesToSignCache == nil {
		bismuth.AddCertificatesToSignCache = func(certificates []*BismuthCertificates) {
			// do nothing
		}
	}

	if bismuth.ConnectToServer == nil {
		bismuth.CheckIfCertificatesAreSigned = true

		bismuth.ConnectToServer = func(address string) (net.Conn, error) {
			return net.Dial("tcp", address)
		}
	}

	bismuth.CheckIfCertificatesAreSigned = true

	return nil
}

func (bismuth *BismuthClient) checkIfDomainIsTrusted(servers, advertisedDomains []string) ([]*BismuthSignResultData, error) {
	signResultData := make([]*BismuthSignResultData, len(servers))

	for index, server := range servers {
		baseConn, err := bismuth.ConnectToServer(server)

		if err != nil {
			return signResultData, err
		}

		defer baseConn.Close()

		conn, signResultsForConn, err := bismuth.Conn(baseConn)

		if err != nil {
			return signResultData, err
		}

		isTrusted, err := signingclient.IsDomainTrusted(conn, signResultsForConn.ServerPublicKey.GetFingerprintBytes(), advertisedDomains)

		if signResultsForConn.OverallTrustScore < 50 {
			isTrusted = false
		}

		signResultData[index] = &BismuthSignResultData{
			IsTrusting: isTrusted,
			ChildNodes: []*BismuthSignResultData{
				signResultsForConn.Node,
			},
		}
	}

	return signResultData, nil
}

// Connects to a Bismuth server. This wraps an existing net.Conn interface.
// The returned net.Conn is the server, but over bismuth.
func (bismuth *BismuthClient) Conn(conn net.Conn) (net.Conn, *BismuthSignResults, error) {
	// Yes, I'm aware defer exists. It won't work if I use it in this context. I'll shank anyone that complains
	// Exchange our public keys first

	hostAndIP := conn.RemoteAddr().String()
	hostAndIPColonIndex := strings.Index(hostAndIP, ":")

	if hostAndIPColonIndex == -1 {
		return nil, nil, fmt.Errorf("failed to get colon in remote address")
	}

	host := hostAndIP[:hostAndIPColonIndex]

	ownKey, err := bismuth.PublicKey.GetPublicKey()

	if err != nil {
		conn.Close()
		return nil, nil, err
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
		return nil, nil, err
	}

	if messageMode[0] != core.SendPublicKey {
		conn.Close()
		return nil, nil, fmt.Errorf("server failed to return its public key")
	}

	if _, err = conn.Read(pubKeyLengthBytes); err != nil {
		conn.Close()
		return nil, nil, err
	}

	pubKeyLength = core.Int24ToInt32(pubKeyLengthBytes)
	pubKeyBytes := make([]byte, pubKeyLength)

	if _, err = conn.Read(pubKeyBytes); err != nil {
		conn.Close()
		return nil, nil, err
	}

	serverPublicKey, err := crypto.NewKey(pubKeyBytes)

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	// Then exchange the symmetric key

	conn.Write([]byte{core.SwitchToSymmetricKey})

	if _, err = conn.Read(messageMode); err != nil {
		conn.Close()
		return nil, nil, err
	}

	if messageMode[0] != core.SwitchToSymmetricKey {
		conn.Close()
		return nil, nil, fmt.Errorf("server failed to return symmetric key")
	}

	encryptedSymmKeyLengthInBytes := make([]byte, 3)

	if _, err = conn.Read(encryptedSymmKeyLengthInBytes); err != nil {
		conn.Close()
		return nil, nil, err
	}

	encryptedSymmKeyLength := core.Int24ToInt32(encryptedSymmKeyLengthInBytes)
	encryptedSymmKey := make([]byte, encryptedSymmKeyLength)

	if _, err = conn.Read(encryptedSymmKey); err != nil {
		conn.Close()
		return nil, nil, err
	}

	decHandleForSymmKey, err := bismuth.pgp.Decryption().DecryptionKey(bismuth.PrivateKey).New()

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	decryptedSymmKey, err := decHandleForSymmKey.Decrypt(encryptedSymmKey, crypto.Bytes)

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	symmKeyInfo := decryptedSymmKey.Bytes()

	if symmKeyInfo[0] != core.XChaCha20Poly1305 {
		conn.Close()
		return nil, nil, fmt.Errorf("unsupported encryption method recieved")
	}

	symmKey := symmKeyInfo[1 : chacha20poly1305.KeySize+1]
	aead, err := chacha20poly1305.NewX(symmKey)

	// Request trusted domains

	trustedDomainsRequest := make([]byte, 1)
	trustedDomainsRequest[0] = core.GetTrustedDomains

	encryptedTrustedDomainRequest, err := bismuth.encryptMessage(aead, trustedDomainsRequest)

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	trustedDomainLength := make([]byte, 3)
	core.Int32ToInt24(trustedDomainLength, uint32(len(encryptedTrustedDomainRequest)))

	conn.Write(trustedDomainLength)
	conn.Write(encryptedTrustedDomainRequest)

	if _, err = conn.Read(trustedDomainLength); err != nil {
		conn.Close()
		return nil, nil, err
	}

	encryptedTrustedDomainResponse := make([]byte, core.Int24ToInt32(trustedDomainLength))

	if _, err = conn.Read(encryptedTrustedDomainResponse); err != nil {
		conn.Close()
		return nil, nil, err
	}

	trustedDomainResponse, err := bismuth.decryptMessage(aead, encryptedTrustedDomainResponse)

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	if trustedDomainResponse[0] != core.GetTrustedDomains {
		conn.Close()
		return nil, nil, fmt.Errorf("server failed to return its signing servers")
	}

	trustedDomains := strings.Split(string(trustedDomainResponse[1:]), "\n")

	// Request signing servers

	signingServerRequest := make([]byte, 1)
	signingServerRequest[0] = core.GetSigningServers

	encryptedSigningServerRequest, err := bismuth.encryptMessage(aead, signingServerRequest)

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	signingRequestLength := make([]byte, 3)
	core.Int32ToInt24(signingRequestLength, uint32(len(encryptedSigningServerRequest)))

	conn.Write(signingRequestLength)
	conn.Write(encryptedSigningServerRequest)

	if _, err = conn.Read(signingRequestLength); err != nil {
		conn.Close()
		return nil, nil, err
	}

	encryptedSigningRequestResponse := make([]byte, core.Int24ToInt32(signingRequestLength))

	if _, err = conn.Read(encryptedSigningRequestResponse); err != nil {
		conn.Close()
		return nil, nil, err
	}

	signingServerResponse, err := bismuth.decryptMessage(aead, encryptedSigningRequestResponse)

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	if signingServerResponse[0] != core.GetSigningServers {
		conn.Close()
		return nil, nil, fmt.Errorf("server failed to return its signing servers")
	}

	// Check if the server is signed

	signingServers := strings.Split(string(signingServerResponse[1:]), "\n")
	isServerSelfSigned := len(signingServers)-1 == 0 || len(trustedDomains)-1 == 0

	rootNode := &BismuthSignResultData{
		ChildNodes: []*BismuthSignResultData{},
		IsTrusting: false,
	}

	signResults := BismuthSignResults{
		OverallTrustScore: 0,
		ServerPublicKey:   serverPublicKey,
		Node:              rootNode,
	}

	totalServerCount, passedServerCount := 0, 0

	if bismuth.CheckIfCertificatesAreSigned {
		serverKeyFingerprint := serverPublicKey.GetFingerprint()
		isCertSigned := bismuth.CertificateSignChecker(host, serverKeyFingerprint, isServerSelfSigned)

		if !isServerSelfSigned || !isCertSigned {
			domainTrustResults, err := bismuth.checkIfDomainIsTrusted(signingServers, trustedDomains)

			if err == nil {
				rootNode.ChildNodes = domainTrustResults
			} else {
				fmt.Printf("ERROR: failed to verify servers (%s).\n", err.Error())
				signResults.OverallTrustScore = 0
			}

			totalServerCount, passedServerCount = computeNodes(rootNode.ChildNodes)
		} else if isCertSigned {
			rootNode.IsTrusting = isCertSigned

			totalServerCount, passedServerCount = 1, 1
			rootNode.IsTrusting = true
		}
	} else {
		totalServerCount, passedServerCount = 1, 1
	}

	if totalServerCount != 0 {
		signResults.OverallTrustScore = int((float32(passedServerCount) / float32(totalServerCount)) * 100)
	}

	// After that, we send what host we are connecting to (enables fronting/proxy services)

	hostInformation := make([]byte, 1+len(host))

	hostInformation[0] = core.ClientSendHost
	copy(hostInformation[1:], []byte(host))

	encryptedHostInformationPacket, err := bismuth.encryptMessage(aead, hostInformation)

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	hostInformationSize := make([]byte, 3)

	core.Int32ToInt24(hostInformationSize, uint32(len(encryptedHostInformationPacket)))

	conn.Write(hostInformationSize)
	conn.Write(encryptedHostInformationPacket)

	// Start proxying

	startForwardingPacket := []byte{
		core.InitiateForwarding,
	}

	encryptedForwardPacket, err := bismuth.encryptMessage(aead, startForwardingPacket)

	if err != nil {
		conn.Close()
		return nil, nil, err
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
	}, &signResults, nil
}

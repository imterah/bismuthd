package client

import (
	"fmt"
	"net"
	"strings"

	core "git.greysoh.dev/imterah/bismuthd/commons"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

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

	return nil
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

	// Request trusted proxies

	trustedProxyRequest := make([]byte, 1)
	trustedProxyRequest[0] = core.GetSigningServers

	encryptedTrustedProxyRequest, err := bismuth.encryptMessage(aead, trustedProxyRequest)

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	trustedProxyLength := make([]byte, 3)
	core.Int32ToInt24(trustedProxyLength, uint32(len(encryptedTrustedProxyRequest)))

	conn.Write(trustedProxyLength)
	conn.Write(encryptedTrustedProxyRequest)

	if _, err = conn.Read(trustedProxyLength); err != nil {
		conn.Close()
		return nil, nil, err
	}

	encryptedTrustedProxyResponse := make([]byte, core.Int24ToInt32(trustedProxyLength))

	if _, err = conn.Read(encryptedTrustedProxyResponse); err != nil {
		conn.Close()
		return nil, nil, err
	}

	trustedProxyResponse, err := bismuth.decryptMessage(aead, encryptedTrustedProxyResponse)

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	if trustedProxyResponse[0] != core.GetSigningServers {
		conn.Close()
		return nil, nil, fmt.Errorf("server failed to return its signing servers")
	}

	signingServers := strings.Split(string(trustedProxyResponse[1:]), "\n")
	isServerSelfSigned := len(trustedProxyResponse)-1 == 0

	if !isServerSelfSigned {
		fmt.Printf("acquired signing servers: '%s'\n", strings.Join(signingServers, ", "))
	} else {
		fmt.Println("server is self signed, not printing (non-existent) signing servers")
	}

	signResults := BismuthSignResults{
		OverallTrustScore: 100,
		ServerPublicKey:   serverPublicKey,
	}

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

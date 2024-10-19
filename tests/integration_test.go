package bismuthd_test

import (
	"bytes"
	mathRand "math/rand"

	"crypto/rand"
	"net"
	"strconv"
	"testing"

	"git.greysoh.dev/imterah/bismuthd/client"
	"git.greysoh.dev/imterah/bismuthd/commons"
	"git.greysoh.dev/imterah/bismuthd/server"
)

var testProtocolTxRxBufCount = 32

// Tests protocol transmitting and receiving
// This is designed to be a nightmare scenario for the protocol to push the limits on what would be possible.
func TestProtocolTxRx(t *testing.T) {
	pubKeyCli, privKeyCli, err := CreateKeyring("alice", "alice@contoso.com")

	if err != nil {
		t.Fatalf("failed to generate 1st pair of keys (%s)", err.Error())
	}

	pubKeyServ, privKeyServ, err := CreateKeyring("bob", "bob@contoso.com")

	if err != nil {
		t.Fatalf("failed to generate 2nd pair of keys (%s)", err.Error())
	}

	t.Log("created keyrings")

	randomDataSlices := [][]byte{}

	for range testProtocolTxRxBufCount {
		randomData := make([]byte, 65535)
		_, err = rand.Read(randomData)

		if err != nil {
			t.Fatalf("failed to generate random data (%s)", err.Error())
		}

		randomDataSlices = append(randomDataSlices, randomData)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		t.Fatalf("failed to listen on TCP for localhost (%s)", err.Error())
	}

	bismuth, err := server.NewBismuthServer(pubKeyServ, privKeyServ, []string{}, commons.XChaCha20Poly1305, func(conn net.Conn) error {
		for entryCount, randomDataSlice := range randomDataSlices {
			_, err = conn.Write(randomDataSlice)

			if err != nil {
				t.Fatalf("failed to send randomDataSlice entry #%d (%s)", entryCount+1, err.Error())
			}
		}

		return nil
	})

	// TODO: fix these warnings?
	go func() {
		conn, err := listener.Accept()

		if err != nil {
			t.Fatalf("failed to accept connection from listener (%s)", err.Error())
		}

		err = bismuth.HandleProxy(conn)

		if err != nil && err.Error() != "EOF" {
			t.Fatalf("failed to handle proxy in Bismuth (%s)", err.Error())
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	bismuthClient, err := client.New(pubKeyCli, privKeyCli)

	if err != nil {
		t.Fatalf("failed to initialize bismuthClient (%s)", err.Error())
	}

	originalConn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))

	if err != nil {
		t.Fatalf("failed to connect to bismuth server (%s)", err.Error())
	}

	conn, err := bismuthClient.Conn(originalConn)

	if err != nil {
		t.Fatalf("bismuth client failed to handshake when connecting to server (%s)", err.Error())
	}

	// Now the real fun begins

	for index, realBuffer := range randomDataSlices {
		bufferSize := len(realBuffer)

		totalBufferRead := 0
		readBuffer := make([]byte, bufferSize)

		for totalBufferRead != bufferSize {
			randBufSize := mathRand.Intn(bufferSize - totalBufferRead)

			if randBufSize == bufferSize {
				continue
			} else if randBufSize == 0 {
				randBufSize = 1
			}

			actualReadSize, err := conn.Read(readBuffer[totalBufferRead : randBufSize+totalBufferRead])

			if err != nil {
				t.Fatalf("bismuth client failed to read in random slice #%d (%s)", index+1, err.Error())
			}

			if actualReadSize > randBufSize {
				t.Fatalf("bismuth client is misreporting read size (expecting n < %d, recieved n (%d) > %d in random slice #%d", randBufSize, actualReadSize, randBufSize, index+1)
			}

			totalBufferRead += actualReadSize
		}

		if !bytes.Equal(realBuffer, readBuffer) {
			t.Fatalf("buffers are different (in random slice #%d)", index+1)
		}

		t.Logf("buffer #%d passed!", index+1)
	}
}

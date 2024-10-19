// Shared connection handler after both the client and server handshake successfully

package commons

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"
)

// Maximum size for a TCP packet
var ConnStandardMaxBufSize = 65535
var cryptHeaderSize = 43

// Connection used after both the Bismuth client and server negotiate and start
// transmitting data.
//
// Note that using this has the same API as the net.Conn, but it isn't conformant to
// the interface due to using pointers rather than copies to access the struct.
//
// If you need the same interface, wrap this in WrappedBismuthConn.
// Wrapping BismuthConn is done automatically by the client and server.
type BismuthConn struct {
	Aead       cipher.AEAD
	PassedConn net.Conn

	lock *sync.Mutex

	initDone bool

	contentBuf     []byte
	contentBufPos  int
	contentBufSize int

	// Maximum buffer size to be used to internally buffer packets
	MaxBufSize int
	// If true, it enables using the content buffer maximum size
	// instead of the TCP packet maximum size
	AllowNonstandardPacketSizeLimit bool
}

func (bmConn *BismuthConn) DoInitSteps() {
	bmConn.lock = &sync.Mutex{}
	bmConn.contentBuf = make([]byte, bmConn.MaxBufSize)

	bmConn.initDone = true
}

func (bmConn *BismuthConn) encryptMessage(msg []byte) ([]byte, error) {
	nonce := make([]byte, bmConn.Aead.NonceSize(), bmConn.Aead.NonceSize()+len(msg)+bmConn.Aead.Overhead())

	if _, err := rand.Read(nonce); err != nil {
		return []byte{}, err
	}

	encryptedMsg := bmConn.Aead.Seal(nonce, nonce, msg, nil)
	return encryptedMsg, nil
}

func (bmConn *BismuthConn) decryptMessage(encMsg []byte) ([]byte, error) {
	if len(encMsg) < bmConn.Aead.NonceSize() {
		return []byte{}, fmt.Errorf("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := encMsg[:bmConn.Aead.NonceSize()], encMsg[bmConn.Aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	decryptedData, err := bmConn.Aead.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return []byte{}, err
	}

	return decryptedData, nil
}

// After you update the property `bmConn.MaxBufSize`, call this function to resize the content buffer
func (bmConn *BismuthConn) ResizeContentBuf() error {
	if !bmConn.initDone {
		return fmt.Errorf("bmConn not initialized")
	}

	bmConn.lock.Lock()

	if bmConn.contentBufSize != 0 {
		// TODO: switch this to do append() instead, when I finally decide to consider this "optimization" in the main buffer logic
		// This code below basically, instead of growing it, gets the actually unused cache data, then grows it and copies it over.
		//
		// This is probably unneccesary, but it saves some hassle I guess.
		currentContentBufData := bmConn.contentBuf[bmConn.contentBufPos:bmConn.contentBufSize]
		bmConn.contentBufSize = bmConn.contentBufSize - bmConn.contentBufPos
		bmConn.contentBufPos = 0

		bmConn.contentBuf = make([]byte, bmConn.MaxBufSize)
		copy(bmConn.contentBuf[len(currentContentBufData):], currentContentBufData)
	} else {
		bmConn.contentBuf = make([]byte, bmConn.MaxBufSize)
	}

	bmConn.lock.Unlock()

	return nil
}

// Reads specifically from the buffer only. If nothing is in the buffer, nothing is returned.
func (bmConn *BismuthConn) ReadFromBuffer(b []byte) (n int, err error) {
	bmConn.lock.Lock()
	defer bmConn.lock.Unlock()

	calcContentBufSize := bmConn.contentBufSize - bmConn.contentBufPos
	providedBufferSize := len(b)

	if bmConn.contentBufSize == 0 {
		return 0, nil
	}

	if calcContentBufSize <= providedBufferSize {
		copy(b, bmConn.contentBuf[bmConn.contentBufPos:bmConn.contentBufSize])

		bmConn.contentBufPos = 0
		bmConn.contentBufSize = 0
		bmConn.contentBuf = make([]byte, bmConn.MaxBufSize)

		return calcContentBufSize, nil
	} else if calcContentBufSize > providedBufferSize {
		newContentBufSize := bmConn.contentBufPos + providedBufferSize
		copy(b, bmConn.contentBuf[bmConn.contentBufPos:newContentBufSize])

		bmConn.contentBufPos = newContentBufSize

		return providedBufferSize, nil
	}

	return 0, nil
}

// Reads specifically from the network. Be careful as using only this may overflow the buffer.
func (bmConn *BismuthConn) ReadFromNetwork(b []byte) (n int, err error) {
	bmConn.lock.Lock()
	defer bmConn.lock.Unlock()

	bufferSize := len(b)

	encryptedContentLengthBytes := make([]byte, 3)

	if _, err = bmConn.PassedConn.Read(encryptedContentLengthBytes); err != nil {
		return 0, err
	}

	encryptedContentLength := Int24ToInt32(encryptedContentLengthBytes)
	encryptedContent := make([]byte, encryptedContentLength)

	// Check to see if we can fit the packet inside either:
	//   - the max TCP packet size (64k) if 'AllowNonstandardPacketSizeLimit' isn't set; or
	//   - the max buffer size if 'AllowNonstandardPacketSizeLimit' is set
	// We check AFTER we read to make sure that we don't corrupt any future packets, because if we don't read the packet,
	// it will think that the actual packet will be the start of the packet, and that would cause loads of problems.
	if !bmConn.AllowNonstandardPacketSizeLimit && encryptedContentLength > uint32(65535+cryptHeaderSize) {
		return 0, fmt.Errorf("packet too large")
	} else if bmConn.AllowNonstandardPacketSizeLimit && encryptedContentLength > uint32(bmConn.MaxBufSize) {
		return 0, fmt.Errorf("packet too large")
	}

	totalPosition := 0

	for totalPosition != int(encryptedContentLength) {
		currentPosition, err := bmConn.PassedConn.Read(encryptedContent[totalPosition:encryptedContentLength])
		totalPosition += currentPosition

		if err != nil {
			return 0, err
		}
	}

	decryptedContent, err := bmConn.decryptMessage(encryptedContent)
	decryptedContentSize := len(decryptedContent)

	calcSize := min(decryptedContentSize, bufferSize)
	copy(b[:calcSize], decryptedContent)

	if bufferSize < int(decryptedContentSize) {
		newSlice := decryptedContent[calcSize:]

		if bmConn.contentBufSize+len(newSlice) > bmConn.MaxBufSize {
			return 0, fmt.Errorf("ran out of room in the buffer to store data! (can't overflow the buffer...)")
		}

		copy(bmConn.contentBuf[bmConn.contentBufSize:bmConn.contentBufSize+len(newSlice)], newSlice)
		bmConn.contentBufSize += len(newSlice)
	}

	if err != nil {
		return calcSize, err
	}

	return calcSize, nil
}

// Reads from the Bismuth connection, using both the buffered and network methods
func (bmConn *BismuthConn) Read(b []byte) (n int, err error) {
	if !bmConn.initDone {
		return 0, fmt.Errorf("bmConn not initialized")
	}

	bufferReadSize, err := bmConn.ReadFromBuffer(b)

	if err != nil {
		return bufferReadSize, err
	}

	if bufferReadSize == len(b) {
		return bufferReadSize, nil
	}

	networkReadSize, err := bmConn.ReadFromNetwork(b[bufferReadSize:])

	if err != nil {
		return bufferReadSize + networkReadSize, err
	}

	return bufferReadSize + networkReadSize, nil
}

// Encrypts and sends off a message
func (bmConn *BismuthConn) Write(b []byte) (n int, err error) {
	encryptedMessage, err := bmConn.encryptMessage(b)

	if err != nil {
		return 0, err
	}

	encryptedMessageSize := make([]byte, 3)
	Int32ToInt24(encryptedMessageSize, uint32(len(encryptedMessage)))

	bmConn.PassedConn.Write(encryptedMessageSize)
	bmConn.PassedConn.Write(encryptedMessage)

	return len(b), nil
}

func (bmConn *BismuthConn) Close() error {
	return bmConn.PassedConn.Close()
}

func (bmConn *BismuthConn) LocalAddr() net.Addr {
	return bmConn.PassedConn.LocalAddr()
}

func (bmConn *BismuthConn) RemoteAddr() net.Addr {
	return bmConn.PassedConn.RemoteAddr()
}

func (bmConn *BismuthConn) SetDeadline(time time.Time) error {
	return bmConn.PassedConn.SetDeadline(time)
}

func (bmConn *BismuthConn) SetReadDeadline(time time.Time) error {
	return bmConn.PassedConn.SetReadDeadline(time)
}

func (bmConn *BismuthConn) SetWriteDeadline(time time.Time) error {
	return bmConn.PassedConn.SetWriteDeadline(time)
}

// Wrapped BismuthConn struct. This is conformant to net.Conn, unlike above.
// To get the raw Bismuth struct, just get the Bismuth property:
//
// `bmConn.Bismuth` -> `BismuthConn`
type BismuthConnWrapped struct {
	Bismuth *BismuthConn
}

func (bmConn BismuthConnWrapped) Read(b []byte) (n int, err error) {
	return bmConn.Bismuth.Read(b)
}

func (bmConn BismuthConnWrapped) Write(b []byte) (n int, err error) {
	return bmConn.Bismuth.Write(b)
}

func (bmConn BismuthConnWrapped) Close() error {
	return bmConn.Bismuth.Close()
}

func (bmConn BismuthConnWrapped) LocalAddr() net.Addr {
	return bmConn.Bismuth.LocalAddr()
}

func (bmConn BismuthConnWrapped) RemoteAddr() net.Addr {
	return bmConn.Bismuth.RemoteAddr()
}

func (bmConn BismuthConnWrapped) SetDeadline(time time.Time) error {
	return bmConn.Bismuth.SetDeadline(time)
}

func (bmConn BismuthConnWrapped) SetReadDeadline(time time.Time) error {
	return bmConn.Bismuth.SetReadDeadline(time)
}

func (bmConn BismuthConnWrapped) SetWriteDeadline(time time.Time) error {
	return bmConn.Bismuth.SetWriteDeadline(time)
}

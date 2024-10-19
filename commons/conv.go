// Conversion libraries for 24 bit numbering instead of 32 bit numbering

package commons

// Converts a 24 bit unsigned integer stored in a big-endian byte array to a 32 bit unsigned integer.
func Int24ToInt32(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

// Converts a 32 bit unsigned integer to a 24 bit unsigned integer in a byte array using big-endian ordering.
func Int32ToInt24(b []byte, int uint32) {
	b[0] = uint8((int >> 16) & 0xff)
	b[1] = uint8((int >> 8) & 0xff)
	b[2] = uint8(int & 0xff)
}

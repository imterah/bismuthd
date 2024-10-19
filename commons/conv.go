package commons

func Int24ToInt32(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func Int32ToInt24(b []byte, int uint32) {
	b[0] = uint8((int >> 16) & 0xff)
	b[1] = uint8((int >> 8) & 0xff)
	b[2] = uint8(int & 0xff)
}

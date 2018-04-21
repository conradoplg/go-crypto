package sha3

import (
	"encoding/binary"
	"hash"
)

func leftEncode(out hash.Hash, x int) int {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(x))
	xLen := 1
	for b[len(b)-xLen-1] != 0 && xLen < len(b) {
		xLen++
	}
	out.Write([]byte{byte(xLen)})
	out.Write(b[len(b)-xLen:])
	return xLen + 1
}

func rightEncode(out hash.Hash, x int) int {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(x))
	xLen := 1
	for b[len(b)-xLen-1] != 0 && xLen < len(b) {
		xLen++
	}
	out.Write(b[len(b)-xLen:])
	out.Write([]byte{byte(xLen)})
	return xLen + 1

}

func encodeString(out hash.Hash, s []byte) int {
	size := leftEncode(out, len(s)*8)
	out.Write(s)
	return size + len(s)
}

func bytepadStart(out hash.Hash, w int) int {
	return leftEncode(out, w)
}

func bytepadEnd(out hash.Hash, written, w int) {
	for ; written%w != 0; written++ {
		out.Write([]byte{0})
	}
}

type cshake struct {
	*state
	initialState *state
}

func newCShake(rate, outputLen int, functionName, customizationString []byte) *cshake {
	if len(functionName) == 0 && len(customizationString) == 0 {
		return &cshake{NewShake128().(*state), nil}
	}
	s := &state{rate: rate, outputLen: outputLen, dsbyte: 0x04}
	written := bytepadStart(s, rate)
	written += encodeString(s, functionName)
	written += encodeString(s, customizationString)
	bytepadEnd(s, written, rate)
	return &cshake{s, s.clone()}
}

func (c *cshake) Reset() {
	c.state = c.initialState.clone()
}

type kmac struct {
	*cshake
}

func NewKMAC128(key []byte, outputLen int, customizationString []byte) hash.Hash {
	return newKMAC(key, outputLen, customizationString, 168)
}

func NewKMAC256(key []byte, outputLen int, customizationString []byte) hash.Hash {
	return newKMAC(key, outputLen, customizationString, 136)
}

func newKMAC(key []byte, outputLen int, customizationString []byte, rate int) hash.Hash {
	c := newCShake(rate, outputLen, []byte("KMAC"), customizationString)
	written := bytepadStart(c, c.rate)
	written += encodeString(c, key)
	bytepadEnd(c, written, c.rate)
	c.initialState = c.clone()
	return &kmac{c}
}

func (k *kmac) Sum(b []byte) []byte {
	s := k.state.clone()
	rightEncode(s, k.outputLen*8)
	return s.Sum(b)
}

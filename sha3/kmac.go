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
}

func newCShake(rate, outputLen int, functionName, customizationString []byte) *cshake {
	if len(functionName) == 0 && len(customizationString) == 0 {
		return &cshake{NewShake128().(*state)}
	}
	s := &state{rate: rate, outputLen: outputLen, dsbyte: 0x04}
	written := bytepadStart(s, rate)
	written += encodeString(s, functionName)
	written += encodeString(s, customizationString)
	bytepadEnd(s, written, rate)
	return &cshake{s}
}

type kmac struct {
	*cshake
	key []byte
}

func NewKMAC128(key []byte, outputLen int, customizationString []byte) hash.Hash {
	k := &kmac{newCShake(168, outputLen, []byte("KMAC"), customizationString), key}
	k.Reset()
	return k
}

func NewKMAC256(key []byte, outputLen int, customizationString []byte) hash.Hash {
	k := &kmac{newCShake(136, outputLen, []byte("KMAC"), customizationString), key}
	k.Reset()
	return k
}

func (k *kmac) Reset() {
	written := bytepadStart(k, k.rate)
	written += encodeString(k, k.key)
	bytepadEnd(k, written, k.rate)
}

func (k *kmac) Sum(b []byte) []byte {
	s := k.state.clone()
	rightEncode(s, k.outputLen*8)
	return s.Sum(b)
}

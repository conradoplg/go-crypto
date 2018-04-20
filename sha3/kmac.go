package sha3

import (
	"encoding/binary"
	"hash"
)

func leftEncode(out []byte, x int) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(x))
	xLen := 1
	for b[len(b)-xLen-1] != 0 && xLen < len(b) {
		xLen++
	}
	out = append(out, byte(xLen))
	return append(out, b[len(b)-xLen:]...)
}

func rightEncode(out []byte, x int) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(x))
	xLen := 1
	for b[len(b)-xLen-1] != 0 && xLen < len(b) {
		xLen++
	}
	out = append(out, b[len(b)-xLen:]...)
	return append(out, byte(xLen))

}

func encodeString(out, s []byte) []byte {
	out = leftEncode(out, len(s)*8)
	out = append(out, s...)
	return out
}

func bytepad(out, x []byte, w int) []byte {
	out = leftEncode(out, w)
	out = append(out, x...)
	for len(out)%w != 0 {
		out = append(out, 0)
	}
	return out
}

type cshake struct {
	*state
	header []byte
}

func newCShake128(outputLen int, functionName, customizationString []byte) *cshake {
	if len(functionName) == 0 && len(customizationString) == 0 {
		return &cshake{NewShake128().(*state), nil}
	}
	var header []byte
	header = encodeString(header, functionName)
	header = encodeString(header, customizationString)
	header = bytepad(nil, header, 168)
	return &cshake{&state{rate: 168, outputLen: outputLen, dsbyte: 0x04}, header}
}

type kmac struct {
	*cshake
	key []byte
}

func NewKMAC128(key []byte, outputLen int, customizationString []byte) hash.Hash {
	k := &kmac{newCShake128(outputLen, []byte("KMAC"), customizationString), key}
	k.Reset()
	return k
}

func (k *kmac) Reset() {
	k.Write(k.header)
	k.Write(bytepad(nil, encodeString(nil, k.key), 168))
}

func (k *kmac) Sum(b []byte) []byte {
	s := k.state.clone()
	s.Write(rightEncode(nil, k.outputLen*8))
	return s.Sum(b)
}

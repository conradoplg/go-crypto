package sha3

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKMAC128(t *testing.T) {
	key, _ := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
	data, _ := hex.DecodeString("00010203")
	s := []byte{}
	tag, _ := hex.DecodeString("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E")

	mac := NewKMAC128(key, len(tag), s)

	mac.Write(data)
	computedTag := mac.Sum(nil)
	if !bytes.Equal(tag, computedTag) {
		t.Errorf("got %x, want %x", computedTag, tag)
	}
}

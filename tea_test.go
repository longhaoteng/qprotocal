package qprotocal

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestEncrypt(t *testing.T) {
	data, err := encrypt(
		[]byte("\x00\x03\xec\xc1\xeb\xf0\x00\x00\x00\x05\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00D\x9b%7]\x8f\x83{\x00\x00\x00\x00\x01\xe1\n\xdc9I\xbaY\xab\xbeV\xe0W\xf2\x0f\x88>\xbb\xbfT\xb9\x9c\xa8^tA4\xde\xcdp\xc5\xef\xb8\x00\x00\x00\x00\x01866819027236657S\x9f\x02 \x01\x00\x00\x00\x00\x00"),
		[]byte("!\x85'j\x1dn\xe6I:kP\x03V[W\x9b"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("wj{\x8e\xd7W\xb8o\xd8z\xa7\xc0\xa5\x0c\xea\x80=9\n\x14\xc1\x05\xc6;)\xb8lq\xa1?\xf0\xcf\xe0\xfe{\x02\xe7zk.\xf9\x0f\xbf\x19\xe84\x0b0fp\xa5\xd3($\xef\xf9\xf6\xc8\x94\xee\xba\xb0\xe1\xbcS\xb4/\xe4m\xc4\x88\xc9\xff\xb2y\xf8\x03\xff;\x91\x9f}\x86.\xba?q]:~O\x15\x93^\x9b.4\xcdpt\xf3\x82\xc8\x1c\x9cv\xc1\xe5\xd4\x03\xee\xf6")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestDecrypt(t *testing.T) {
	cipherText, err := hex.DecodeString("86fb4c80be369eb346bb1a78d6fb6f523287166fc2e6a924d9d28039a1cb4ca3ce0afb3541d97efaed637bf4d4821b3c1d39b75d460932cb5bbb65f28686dba9988874c7168dc9155a6552df9a023841865d22621343be2aac3caf0d6c7a79575fd60c0dd34ff99f9540a36f007f54d0b76fa3df0a00abbcf3d413c9f95b89ab")
	if err != nil {
		t.Fatal(err)
	}
	data, err := decrypt(
		cipherText,
		[]byte("\x95|:\xaf\xbfo\xaf\x1d,/\x19\xa5\xea\x04\xe5\x1c"))
	if err != nil {
		t.Fatal(err)
	}
	refer := "00090100020146004200000001000ce799bbe5bd95e5a4b1e8b4a5002ae5b890e58fb7e68896e5af86e7a081e99499e8afafefbc8ce8afb7e9878de696b0e8be93e585a5e3808200000000050800220100000bb8001b020000001020029f5308100000000100000000449b253700000001"
	if !strings.EqualFold(hex.EncodeToString(data), refer) {
		t.Errorf("%s", hex.EncodeToString(data))
		t.Errorf("%s", refer)
	}
}

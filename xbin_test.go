package qprotocal

import (
	"bytes"
	"testing"
)

func TestGetRandomHex(t *testing.T) {
	data, err := getRandomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8\xc8")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestGetMd5Value(t *testing.T) {
	data := getMd5Value([]byte("123456"))
	refer := []byte("\xe1\n\xdc9I\xbaY\xab\xbeV\xe0W\xf2\x0f\x88>")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

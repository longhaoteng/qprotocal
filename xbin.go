package qprotocal

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

func getRandomHex(length int) ([]byte, error) {
	var randomHex string
	for i := 0; i < length; i++ {
		rand.Seed(time.Now().UnixNano())
		random := rand.Intn(255)
		//random := 200
		randomHex += fmt.Sprintf("%02x", random)
	}
	data, err := hex.DecodeString(randomHex)
	if err != nil {
		return nil, err
	}
	return data, err
}

func getMd5Value(src []byte) []byte {
	m := md5.New()
	m.Write(src)
	return m.Sum(nil)
}

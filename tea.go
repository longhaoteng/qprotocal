package qprotocal

import (
	"bytes"
	"github.com/lunixbochs/struc"
	"math/rand"
	"time"
)

var (
	// key schedule constant
	delta = 0x9E3779B9
	round = 16
	op    = 0xFFFFFFFF
	// append 7 '\0' in the end of the message
	flag = make([]byte, 7)
)

// xor per 8 bytes
func xor(a, b []byte) ([]byte, error) {
	block := make([]byte, 0)
	for i := 0; i < 8; i++ {
		data, err := structPack(&struct{ Ex uint `struc:"uint8,little"` }{Ex: uint(a[i] ^ b[i])})
		if err != nil {
			return nil, err
		}
		block = byteJoin(block, data)
	}
	return block, nil
}

func encipher(t, shareKey []byte) ([]byte, error) {
	sum := delta

	keys := &struct {
		Ex1 uint `struc:"uint32"`
		Ex2 uint `struc:"uint32"`
		Ex3 uint `struc:"uint32"`
		Ex4 uint `struc:"uint32"`
	}{}
	err := struc.Unpack(bytes.NewBuffer(shareKey), keys)
	if err != nil {
		return nil, err
	}

	type Uint32 struct {
		Uint32One uint `struc:"uint32"`
		Uint32Two uint `struc:"uint32"`
	}
	uInt32 := &Uint32{}
	err = struc.Unpack(bytes.NewBuffer(t), uInt32)
	if err != nil {
		return nil, err
	}

	uint32One := int(uInt32.Uint32One)
	uint32Two := int(uInt32.Uint32Two)
	key1 := int(keys.Ex1)
	key2 := int(keys.Ex2)
	key3 := int(keys.Ex3)
	key4 := int(keys.Ex4)
	for i := 0; i < round; i++ {
		uint32One += (((uint32Two << 4) & 0xFFFFFFF0) + key1) ^ (
			uint32Two + sum) ^ (((uint32Two >> 5) & 0x07ffffff) + key2)
		uint32Two += (((uint32One << 4) & 0xFFFFFFF0) + key3) ^ (
			uint32One + sum) ^ (((uint32One >> 5) & 0x07ffffff) + key4)
		sum += delta
	}
	uint32One &= op
	uint32Two &= op

	data, err := structPack(&Uint32{uint(uint32One), uint(uint32Two)})
	if err != nil {
		return nil, err
	}

	return data, nil
}

func decipher(t, shareKey []byte) ([]byte, error) {
	sum := (delta << 4) & op

	keys := &struct {
		Ex1 uint `struc:"uint32"`
		Ex2 uint `struc:"uint32"`
		Ex3 uint `struc:"uint32"`
		Ex4 uint `struc:"uint32"`
	}{}
	err := struc.Unpack(bytes.NewBuffer(shareKey), keys)
	if err != nil {
		return nil, err
	}

	type Uint32 struct {
		Uint32One uint `struc:"uint32"`
		Uint32Two uint `struc:"uint32"`
	}
	uInt32 := &Uint32{}
	err = struc.Unpack(bytes.NewBuffer(t), uInt32)
	if err != nil {
		return nil, err
	}

	uint32One := int(uInt32.Uint32One)
	uint32Two := int(uInt32.Uint32Two)
	key1 := int(keys.Ex1)
	key2 := int(keys.Ex2)
	key3 := int(keys.Ex3)
	key4 := int(keys.Ex4)
	for i := 0; i < round; i++ {
		uint32Two -= (((uint32One << 4) & 0xFFFFFFF0) + key3) ^ (
			uint32One + sum) ^ (((uint32One >> 5) & 0x07ffffff) + key4)
		uint32One -= (((uint32Two << 4) & 0xFFFFFFF0) + key1) ^ (
			uint32Two + sum) ^ (((uint32Two >> 5) & 0x07ffffff) + key2)
		sum -= delta
	}
	uint32One &= op
	uint32Two &= op

	data, err := structPack(&Uint32{uint(uint32One), uint(uint32Two)})
	if err != nil {
		return nil, err
	}

	return data, nil
}

func encrypt(cleartext, shareKey []byte) ([]byte, error) {
	cleartextLength := len(cleartext)

	// to count the number of fill bytes
	paddingLength := (8 - (cleartextLength + 2)) % 8
	fill := 0
	if paddingLength < 0 {
		fill = 8
	}
	paddingLength += 2 + fill

	// filling the random bytes
	paddingHex := make([]byte, 0)
	for i := 0; i < paddingLength; i++ {
		rand.Seed(time.Now().UnixNano())
		random := rand.Intn(254-1) + 1
		//random := 200
		data, err := structPack(&struct{ Random byte `struc:"byte,little"` }{Random: byte(random)})
		if err != nil {
			return nil, err
		}
		paddingHex = byteJoin(paddingHex, data)
	}

	// merge
	data, err := structPack(&struct{ Ex byte `struc:"byte,little"` }{Ex: byte((paddingLength - 2) | 0xF8)})
	if err != nil {
		return nil, err
	}
	paddedCleartext := byteJoins(data, paddingHex, cleartext, flag)

	b1, b2 := make([]byte, 8), make([]byte, 8)
	var result []byte
	for i := 0; i < len(paddedCleartext); i += 8 {
		t, err := xor(paddedCleartext[i:i+8], b1)
		if err != nil {
			return nil, err
		}
		encipher, err := encipher(t, shareKey)
		if err != nil {
			return nil, err
		}
		b1, err = xor(encipher, b2)
		if err != nil {
			return nil, err
		}
		b2 = t
		result = byteJoin(result, b1)
	}
	return result, nil
}

func decrypt(cipherText, shareKey []byte) ([]byte, error) {
	cipherTextLength := len(cipherText)

	preCrypt := cipherText[0:8]
	prePlain, err := decipher(preCrypt, shareKey)
	if err != nil {
		return nil, err
	}

	pos := (prePlain[0] & 0x07) + 2
	result := make([]byte, len(prePlain))
	copy(result, prePlain)

	for i := 8; i < cipherTextLength; i += 8 {
		ex1, err := xor(cipherText[i:i+8], prePlain)
		if err != nil {
			return nil, err
		}
		decipher, err := decipher(ex1, shareKey)
		if err != nil {
			return nil, err
		}
		ex2, err := xor(decipher, preCrypt)
		if err != nil {
			return nil, err
		}
		prePlain, err = xor(ex2, preCrypt)
		if err != nil {
			return nil, err
		}
		preCrypt = cipherText[i : i+8]
		result = byteJoin(result, ex2)
	}
	if bytes.Equal(result[len(result)-7:], make([]byte, 7)) {
		return result[pos+1 : len(result)-7], nil
	} else {
		return result, nil
	}
}

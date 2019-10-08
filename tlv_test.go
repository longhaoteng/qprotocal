package qprotocal

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestTlv1(t *testing.T) {
	data, err := tlv1(1151018295, 1569469005)
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x00\x01\x00\x14\x00\x01W\xae\xfb[D\x9b%7]\x8c2M\x00\x00\x00\x00\x00\x00")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv2(t *testing.T) {
	data, err := tlv2("1234", []byte("\x00\x02\x00\x00\x00\x00\x04\x00\x18"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x00\x02\x00\x13\x00\x00\x00\x041234\x00\t\x00\x02\x00\x00\x00\x00\x04\x00\x18")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv8(t *testing.T) {
	data, err := tlv8()
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x00\x08\x00\x08\x00\x00\x00\x00\x08\x04\x00\x00")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv18(t *testing.T) {
	data, err := tlv18(1151018295)
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x00\x18\x00\x16\x00\x01\x00\x00\x06\x00\x00\x00\x00\x10\x00\x00\x00\x00D\x9b%7\x00\x00\x00\x00")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv100(t *testing.T) {
	data, err := tlv100(537042771)
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01\x00\x00\x16\x00\x01\x00\x00\x00\x05\x00\x00\x00\x10 \x02\x9fS\x00\x00\x00\x00\x00\x0e\x10\xe0")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv104(t *testing.T) {
	data, err := tlv104([]byte("\x00\x02\x00\x00\x00\x00\x04\x00\x18"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01\x04\x00\t\x00\x02\x00\x00\x00\x00\x04\x00\x18")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv106(t *testing.T) {
	data, err := tlv106(1151018295, []byte("\xe1\n\xdc9I\xbaY\xab\xbeV\xe0W\xf2\x0f\x88>"), []byte("!\x85'j\x1dn\xe6I:kP\x03V[W\x9b"), []byte("0\x89\xf1r\x8a\xf0\x85K\xf6\x16\xc6\xb7\x84\x90\x8b\x01"), []byte("866819027236657"), 1569504458, 537042771)
	if err != nil {
		t.Fatal(err)
	}
	refer := "01060070776a7b8ed757b86feb2243534b0d92a625976a24eb3803a26db997564d07b40119390535bda1d5193764ab14a4838b9c777b80fe503fe1d85177f57a8a5a19572c2d97c6d2841aaf954a067636e6fe64231b6abe683be0b227abea8a9531feae9a92da0567d3b899976a8f8ead98b1bf"
	if !strings.EqualFold(hex.EncodeToString(data), refer) {
		t.Errorf("%s", hex.EncodeToString(data))
		t.Errorf("%s", refer)
	}
	// 1："\x00\x03\x07\xab\xdf\xec\x00\x00\x00\x05\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00D\x9b%7]\x8c\xbc\xca\x00\x00\x00\x00\x01"
	// 2："\x00\x03\x07\xab\xdf\xec\x00\x00\x00\x05\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00D\x9b%7]\x8c\xbc\xca\x00\x00\x00\x00\x01\xe1\n\xdc9I\xbaY\xab\xbeV\xe0W\xf2\x0f\x88>0\x89\xf1r\x8a\xf0\x85K\xf6\x16\xc6\xb7\x84\x90\x8b\x01"
	// 3："\x00\x03\x07\xab\xdf\xec\x00\x00\x00\x05\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00D\x9b%7]\x8c\xbc\xca\x00\x00\x00\x00\x01\xe1\n\xdc9I\xbaY\xab\xbeV\xe0W\xf2\x0f\x88>0\x89\xf1r\x8a\xf0\x85K\xf6\x16\xc6\xb7\x84\x90\x8b\x01\x00\x00\x00\x00\x01"
	// 4："\x00\x03\x07\xab\xdf\xec\x00\x00\x00\x05\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00D\x9b%7]\x8c\xbc\xca\x00\x00\x00\x00\x01\xe1\n\xdc9I\xbaY\xab\xbeV\xe0W\xf2\x0f\x88>0\x89\xf1r\x8a\xf0\x85K\xf6\x16\xc6\xb7\x84\x90\x8b\x01\x00\x00\x00\x00\x01866819027236657S\x9f\x02 "
	// 5："\x00\x03\x07\xab\xdf\xec\x00\x00\x00\x05\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00D\x9b%7]\x8c\xbc\xca\x00\x00\x00\x00\x01\xe1\n\xdc9I\xbaY\xab\xbeV\xe0W\xf2\x0f\x88>0\x89\xf1r\x8a\xf0\x85K\xf6\x16\xc6\xb7\x84\x90\x8b\x01\x00\x00\x00\x00\x01866819027236657S\x9f\x02 \x01\x00\x00\x00\x00\x00"
}

func TestTlv107(t *testing.T) {
	data, err := tlv107()
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01\x07\x00\x06\x00\x00\x00\x00\x00\x01")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv108(t *testing.T) {
	kSid, err := hex.DecodeString("93AC689396D57E5F9496B81536AAFE91")
	if err != nil {
		t.Fatal(err)
	}
	data, err := tlv108(kSid)
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01\x08\x00\x00")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv109(t *testing.T) {
	data, err := tlv109([]byte("866819027236657"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01\t\x00\x0f866819027236657")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv114Get0058(t *testing.T) {
	data, err := tlv114Get0058([]byte("\x00\x01]\x8e\xd5\x10\x00X \xa3\xde\xcf\x8e\x91R\xd0\r\xc0\x8c@Z\xff\xc5\xd4}\xd4;\xcf\x8fn\xa1\x9fw\x89\xe6\x08G?o\xc5/H\x11\xd3\xd30\x86D\x0c\xe26\x8f\x87\x9cP\x03\x07\xda\x7f\x9d\xa3\xb6w\x0c\xe9|k\xfa\xa6fnw\x1d\xfc\x0cPz\xd1Bm\xc3\x14\xf3<i|5\xf2\x92\xf9)\xe4\x08N\xb9\x93"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte(" \xa3\xde\xcf\x8e\x91R\xd0\r\xc0\x8c@Z\xff\xc5\xd4}\xd4;\xcf\x8fn\xa1\x9fw\x89\xe6\x08G?o\xc5/H\x11\xd3\xd30\x86D\x0c\xe26\x8f\x87\x9cP\x03\x07\xda\x7f\x9d\xa3\xb6w\x0c\xe9|k\xfa\xa6fnw\x1d\xfc\x0cPz\xd1Bm\xc3\x14\xf3<i|5\xf2\x92\xf9)\xe4\x08N\xb9\x93")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv116(t *testing.T) {
	data, err := tlv116()
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01\x16\x00\n\x00\x00\x00\x7f|\x00\x01\x04\x00\x00")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv124(t *testing.T) {
	data, err := tlv124([]byte("android"), []byte("4.4.4"), []byte("wifi"), 2)
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01$\x00\x1c\x00\x07android\x00\x054.4.4\x00\x02\x00\x00\x00\x00\x00\x04wifi")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv128(t *testing.T) {
	data, err := tlv128([]byte("android"), []byte("866819027236657"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01(\x00%\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x07android\x00\x0f866819027236657\x00\x00")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv141(t *testing.T) {
	data, err := tlv141(2, []byte("wifi"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01A\x00\x0c\x00\x01\x00\x00\x00\x02\x00\x04wifi")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv142(t *testing.T) {
	data, err := tlv142([]byte("com.tencent.mobileqq"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01B\x00\x18\x00\x00\x00\x14com.tencent.mobileqq")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv144(t *testing.T) {
	data, err := tlv144([]byte("QU\x92*6w\xeb\xab\xe5\xcd!{\x9a\x9em\x8e"),
		[]byte("\x01\t\x00\x0f866819027236657"),
		[]byte("\x01$\x00\x1c\x00\x07android\x00\x054.4.4\x00\x02\x00\x00\x00\x00\x00\x04wifi"),
		[]byte("\x01(\x00%\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x07Nexus 5\x00\x0f866819027236657\x00\x00"),
		[]byte("\x01n\x00\x07Nexus 5"))
	if err != nil {
		t.Fatal(err)
	}
	refer := "014400783e1ae398d4c45722f8232e9325df3ee79a22e9df4468d369b418a36f64cf63a7ef3362cb02a1d78c11e82e8048da54d68617b1f1b50e21b45cc1e872b36f7233c60736d5c410f6f7fcf67961df2f1914a5f92db8befeeef1fc7bcfb4aed6d8523d29da8d9486a1db5eb85c102f87c910385f602f5fd67996"
	if !strings.EqualFold(hex.EncodeToString(data), refer) {
		t.Errorf("%s", hex.EncodeToString(data))
		t.Errorf("%s", refer)
	}
}

func TestTlv145(t *testing.T) {
	data, err := tlv145([]byte("866819027236657"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01E\x00\x0f866819027236657")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv147(t *testing.T) {
	data, err := tlv147([]byte("5.8.0.157158"), []byte("\xA6\xB7\x45\xBF\x24\xA2\xC2\x77\x52\x77\x16\xF6\xF3\x6E\xB6\x8D"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01\t\x00$\x00\x00\x00\x10\x00\x0c5.8.0.157158\x00\x10\xa6\xb7E\xbf$\xa2\xc2wRw\x16\xf6\xf3n\xb6\x8d")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv154(t *testing.T) {
	data, err := tlv154(10000)
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01T\x00\x04\x00\x00'\x10")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv16b(t *testing.T) {
	data, err := tlv16b()
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01k\x00\x0f\x00\x01\x00\x0bgame.qq.com")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv16e(t *testing.T) {
	data, err := tlv16e([]byte("android"))
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01n\x00\x07android")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv177(t *testing.T) {
	data, err := tlv177()
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01w\x00\x0e\x01S\xfb\x17\x9b\x00\x075.2.3.0")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv187(t *testing.T) {
	data, err := tlv187()
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01\x87\x00\x10\xf8\xff\x12#n\r\xaf$\x97\xce~\xd6\xa0{\xddh")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv188(t *testing.T) {
	data, err := tlv188()
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01\x88\x00\x10M\xbfe3\xd9\x08\xc2scm\xe5\xcd\xae\x83\xc0C")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

func TestTlv191(t *testing.T) {
	data, err := tlv191()
	if err != nil {
		t.Fatal(err)
	}
	refer := []byte("\x01\x91\x00\x01\x00")
	if !bytes.Equal(data, refer) {
		t.Errorf("%d", data)
		t.Errorf("%d", refer)
	}
}

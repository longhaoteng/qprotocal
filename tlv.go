package qprotocal

import (
	"bytes"
	"github.com/lunixbochs/struc"
	"math/rand"
)

func byteJoin(a, b []byte) []byte {
	return bytes.Join([][]byte{a, b}, []byte(""))
}

func byteJoins(args ...[]byte) []byte {
	b := make([]byte, 0)
	for _, arg := range args {
		b = byteJoin(b, arg)
	}
	return b
}

func tlvPack(cmd int, bin []byte, lenPadding int) ([]byte, error) {
	type Data struct {
		Cmd uint `struc:"uint16"`
		Bin uint `struc:"uint16"`
	}
	data, err := structPack(&Data{uint(cmd), uint(len(bin) + lenPadding)})
	if err != nil {
		return nil, err
	}
	return byteJoin(data, bin), nil
}

func tlvUnPack(qq *QQ, bin []byte) error {
	tlvCount := &h{}
	err := struc.Unpack(bytes.NewBuffer(bin[:2]), tlvCount)
	if err != nil {
		return err
	}

	bin = bin[2:]

	for i := 0; i < int(tlvCount.H); i++ {
		tlvCmd := bin[:2]
		bin = bin[2:]

		tlvLen := &h{}
		err := struc.Unpack(bytes.NewBuffer(bin[:2]), tlvLen)
		if err != nil {
			return err
		}

		bin = bin[2:]
		tlvBin := bin[:int(tlvLen.H)]

		bin = bin[int(tlvLen.H):]

		if bytes.Equal(tlvCmd, []byte("\x01\x0A")) {
			qq.Token004c = tlvBin
		} else if bytes.Equal(tlvCmd, []byte("\x01\x6A")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x06")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x0C")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x0D")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x1F")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x20")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x63")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x65")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x18")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x08")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x14")) {
			token0058, err := tlv114Get0058(tlvBin)
			if err != nil {
				return err
			}
			qq.Token0058 = token0058
		} else if bytes.Equal(tlvCmd, []byte("\x01\x0E")) {
			qq.Mst1Key = tlvBin
		} else if bytes.Equal(tlvCmd, []byte("\x01\x03")) {
			qq.StWeb = tlvBin
		} else if bytes.Equal(tlvCmd, []byte("\x01\x38")) {
		} else if bytes.Equal(tlvCmd, []byte("\x01\x1A")) {
			face := &h{}
			err := struc.Unpack(bytes.NewBuffer(tlvBin[:2]), face)
			if err != nil {
				return err
			}
			qq.Face = face.H

			age := &b{}
			err = struc.Unpack(bytes.NewBuffer(tlvBin[2:3]), age)
			if err != nil {
				return err
			}
			qq.Age = age.B

			gender := &b{}
			err = struc.Unpack(bytes.NewBuffer(tlvBin[3:4]), gender)
			if err != nil {
				return err
			}
			qq.Gender = gender.B

			xLen := &b{}
			err = struc.Unpack(bytes.NewBuffer(tlvBin[4:5]), xLen)
			if err != nil {
				return err
			}

			tlvBin = tlvBin[5:]
			qq.Nick = string(tlvBin[:xLen.B])
		} else if bytes.Equal(tlvCmd, []byte("\x01\x20")) {
			qq.SKey = tlvBin
		} else if bytes.Equal(tlvCmd, []byte("\x01\x36")) {
			qq.VKey = tlvBin
		} else if bytes.Equal(tlvCmd, []byte("\x03\x05")) {
			qq.SessionKey = tlvBin
		} else if bytes.Equal(tlvCmd, []byte("\x01\x43")) {
			qq.Token002c = tlvBin
		} else if bytes.Equal(tlvCmd, []byte("\x01\x64")) {
			qq.Sid = tlvBin
		} else if bytes.Equal(tlvCmd, []byte("\x01\x30")) {
			//time := &L{}
			//err = struc.Unpack(bytes.NewBuffer(tlvBin[2:6]), time)
			//if err != nil {
			//	return err
			//}
			//ip := tlvBin[6:10]
		} else if bytes.Equal(tlvCmd, []byte("\x01\x04")) {
			qq.VerificationToken2 = tlvBin
		} else if bytes.Equal(tlvCmd, []byte("\x01\x05")) {
			len1 := &h{}
			err := struc.Unpack(bytes.NewBuffer(tlvBin[:2]), len1)
			if err != nil {
				return err
			}
			tlvBin := tlvBin[2:]
			qq.VerificationToken1 = tlvBin[:len1.H]
			tlvBin = tlvBin[len1.H:]
			len2 := &h{}
			err = struc.Unpack(bytes.NewBuffer(tlvBin[:2]), len2)
			if err != nil {
				return err
			}
			tlvBin = tlvBin[2:]
			qq.Verification = tlvBin[:len2.H]
		} else if bytes.Equal(tlvCmd, []byte("\x01\x6C")) {
			qq.PsKey = tlvBin
		} else if bytes.Equal(tlvCmd, []byte("\x01\x6D")) {
			qq.SuperKey = tlvBin
		} else {
		}
	}
	return nil
}

func tlv1(uin uint, time int64) ([]byte, error) {
	type Data struct {
		IpVer    uint `struc:"uint16"`
		Random32 uint
		Uin      uint
		Time     uint
		IpAddr   uint
		Ex       uint `struc:"uint16"`
	}
	rand.Seed(time)
	random32 := rand.Intn(4294967295)
	//random32 := 1471085403
	data, err := structPack(&Data{1, uint(random32), uin, uint(time), 0, 0})
	if err != nil {
		return nil, err
	}
	return tlvPack(0x01, data, 0)
}

func tlv2(code string, verificationToken1 []byte) ([]byte, error) {
	data, err := structPack(&i{uint(len(code))})
	if err != nil {
		return nil, err
	}
	tlvData := byteJoin(data, []byte(code))

	data, err = structPack(&h{uint(len(verificationToken1))})
	if err != nil {
		return nil, err
	}

	tlvData = byteJoin(tlvData, data)
	tlvData = byteJoin(tlvData, verificationToken1)
	return tlvPack(0x02, tlvData, 0)
}

func tlv8() ([]byte, error) {
	localId := 0x0804
	data, err := structPack(&struct {
		Ex1     uint `struc:"uint16"`
		LocalId uint
		Ex2     uint `struc:"uint16"`
	}{Ex1: 0, LocalId: uint(localId), Ex2: 0})
	if err != nil {
		return nil, err
	}
	return tlvPack(0x08, data, 0)
}

func tlv18(uin uint) ([]byte, error) {
	type Data struct {
		PingVer      uint `struc:"uint16"`
		SsoVer       uint
		AppId        uint
		AppClientVer uint
		Nin          uint
		Ex1          uint `struc:"uint16"`
		Ex2          uint `struc:"uint16"`
	}
	data, err := structPack(&Data{1, 1536, 0x10, 0, uin, 0, 0})
	if err != nil {
		return nil, err
	}
	return tlvPack(0x18, data, 0)
}

func tlv100(subAppId uint) ([]byte, error) {
	type Data struct {
		DbBufVer         uint `struc:"uint16"`
		SsoVer           uint
		AppId            uint
		SubAppId         uint
		AppClientVersion uint
		MainSigMap       uint
	}
	data, err := structPack(&Data{1, 5, 0x10, subAppId, 0, 0x0E10E0})
	if err != nil {
		return nil, err
	}
	return tlvPack(0x0100, data, 0)
}

func tlv104(verificationToken2 []byte) ([]byte, error) {
	return tlvPack(0x0104, verificationToken2, 0)
}

func tlv106(uin uint, md5Pwd, md5Pwd2, tgtKey, imei []byte, time int64, appId uint) ([]byte, error) {
	type Data struct {
		TgtVer   uint `struc:"uint16"`
		Random32 uint
		Ex1      uint
		Ex2      uint
		Ex3      uint
		Ex4      uint
		Uin      uint
		Time     uint
		Ex5      uint
		Ex6      bool
	}
	random32 := rand.Intn(4294967295)
	//random32 := 128704492
	data, err := structPack(&Data{3, uint(random32), 5, 16, 0, 0, uin, uint(time), 0, true})
	if err != nil {
		return nil, err
	}
	tlvData := byteJoins(data, md5Pwd, tgtKey)

	data, err = structPack(&struct {
		Ex1 uint `struc:"uint,little"`
		Ex2 bool `struc:"bool,little"`
	}{Ex1: 0, Ex2: true})
	if err != nil {
		return nil, err
	}
	tlvData = byteJoin(tlvData, data)

	data, err = structPack(&struct{ AppId uint `struc:"uint,little"` }{AppId: appId})
	if err != nil {
		return nil, err
	}
	tlvData = byteJoins(tlvData, imei, data)

	data, err = structPack(&struct {
		Ex1 uint `struc:"uint,little"`
		Ex2 uint `struc:"uint16,little"`
	}{Ex1: 1, Ex2: 0})
	if err != nil {
		return nil, err
	}
	tlvData = byteJoin(tlvData, data)

	encrypted, err := encrypt(tlvData, md5Pwd2)
	if err != nil {
		return nil, err
	}
	return tlvPack(0x0106, encrypted, 0)
}

func tlv107() ([]byte, error) {

	data, err := structPack(&struct {
		PicType uint `struc:"uint16"`
		Ex1     bool
		Ex2     uint `struc:"uint16"`
		Ex3     bool
	}{PicType: 0, Ex1: false, Ex2: 0, Ex3: true})
	if err != nil {
		return nil, err
	}
	return tlvPack(0x0107, data, 0)
}

func tlv108(kSid []byte) ([]byte, error) {
	//tlvData := kSid
	tlvData := make([]byte, 0)
	return tlvPack(0x0108, tlvData, 0)
}

func tlv109(imei []byte) ([]byte, error) {
	return tlvPack(0x0109, imei, 0)
}

func tlv114Get0058(bin []byte) ([]byte, error) {
	Bin := &h{}
	err := struc.Unpack(bytes.NewBuffer(bin[6:8]), Bin)
	if err != nil {
		return nil, err
	}
	bin = bin[8 : Bin.H+8]
	return bin, nil
}

func tlv116() ([]byte, error) {
	type Data struct {
		Ex                 bool
		MiscBitMap         uint `struc:"uint32"`
		SubSigMap          uint `struc:"uint32"`
		SubAppIdListLength bool
	}
	data, err := structPack(&Data{false, 0x7F7C, 0x010400, false})
	if err != nil {
		return nil, err
	}
	return tlvPack(0x0116, data, 0)
}

func tlv124(osType, osVersion, apn []byte, networkType uint) ([]byte, error) {
	osTypeLen, err := structPack(&h{uint(len(osType))})
	if err != nil {
		return nil, err
	}

	osVersionLen, err := structPack(&h{uint(len(osVersion))})
	if err != nil {
		return nil, err
	}

	networkTypeBin, err := structPack(&h{networkType})
	if err != nil {
		return nil, err
	}

	apnLen, err := structPack(&h{uint(len(apn))})
	if err != nil {
		return nil, err
	}

	simOperatorName := make([]byte, 2)

	tlvData := byteJoins(osTypeLen, osType, osVersionLen, osVersion, networkTypeBin, simOperatorName, simOperatorName, apnLen, apn)

	return tlvPack(0x0124, tlvData, 0)
}

func tlv128(device, imei []byte) ([]byte, error) {
	deviceLen, err := structPack(&h{uint(len(device))})
	if err != nil {
		return nil, err
	}

	imeiLen, err := structPack(&h{uint(len(imei))})
	if err != nil {
		return nil, err
	}

	type Data struct {
		Ex         uint `struc:"uint16"`
		NewInstall bool
		ReadGuid   bool
		GuidChg    bool
		DevReport  uint `struc:"uint32"`
	}
	data, err := structPack(&Data{0, false, true, false, 0x01000000})
	if err != nil {
		return nil, err
	}

	tlvData := byteJoins(data, deviceLen, device, imeiLen, imei, make([]byte, 2))

	return tlvPack(0x0128, tlvData, 0)
}

func tlv141(networkType uint, apn []byte) ([]byte, error) {
	type Data struct {
		Ver             uint `struc:"uint16"`
		SimOperatorName uint `struc:"uint16"`
		NetworkType     uint `struc:"uint16"`
		ApnLen          uint `struc:"uint16"`
	}
	data, err := structPack(&Data{1, 0, networkType, uint(len(apn))})
	if err != nil {
		return nil, err
	}

	tlvData := byteJoins(data, apn)

	return tlvPack(0x0141, tlvData, 0)
}

func tlv142(apkId []byte) ([]byte, error) {
	data, err := structPack(&i{uint(len(apkId))})
	if err != nil {
		return nil, err
	}

	tlvData := byteJoin(data, apkId)
	return tlvPack(0x0142, tlvData, 0)
}

func tlv144(tgtKey, tlv109, tlv124, tlv128, tlv16e []byte) ([]byte, error) {
	data, err := structPack(&h{4})
	if err != nil {
		return nil, err
	}
	encrypted, err := encrypt(byteJoins(data, tlv109, tlv124, tlv128, tlv16e), tgtKey)
	if err != nil {
		return nil, err
	}
	return tlvPack(0x0144, encrypted, 0)
}

func tlv145(imei []byte) ([]byte, error) {
	return tlvPack(0x0145, imei, 0)
}

func tlv147(apkVer, apkSig []byte) ([]byte, error) {
	data, err := structPack(&struct {
		AppId     uint `struc:"uint32"`
		ApkVerLen uint `struc:"uint16"`
	}{AppId: 0x10, ApkVerLen: uint(len(apkVer))})
	if err != nil {
		return nil, err
	}
	tlvData := byteJoin(data, apkVer)

	data, err = structPack(&h{uint(len(apkSig))})
	if err != nil {
		return nil, err
	}

	tlvData = byteJoin(tlvData, data)
	tlvData = byteJoin(tlvData, apkSig)
	return tlvPack(0x0109, tlvData, 0)
}

func tlv154(ssoSeq uint) ([]byte, error) {
	data, err := structPack(&i{ssoSeq})
	if err != nil {
		return nil, err
	}
	return tlvPack(0x0154, data, 0)
}

func tlv16b() ([]byte, error) {
	url := []byte("game.qq.com")

	data, err := structPack(&struct {
		Ver    uint `struc:"uint16"`
		UrlLen uint `struc:"uint16"`
	}{Ver: 1, UrlLen: uint(len(url))})
	if err != nil {
		return nil, err
	}

	tlvData := byteJoin(data, url)
	return tlvPack(0x016b, tlvData, 0)
}

func tlv16e(device []byte) ([]byte, error) {
	return tlvPack(0x016e, device, 0)
}

func tlv177() ([]byte, error) {
	qqVer := []byte("5.2.3.0")

	data, err := structPack(&h{uint(len(qqVer))})
	if err != nil {
		return nil, err
	}

	tlvData := byteJoins([]byte("\x01"), []byte("\x53\xFB\x17\x9B"), data, qqVer)
	return tlvPack(0x0177, tlvData, 0)
}

func tlv187() ([]byte, error) {
	tlvData := []byte("\xF8\xFF\x12\x23\x6E\x0D\xAF\x24\x97\xCE\x7E\xD6\xA0\x7B\xDD\x68")
	return tlvPack(0x0187, tlvData, 0)
}

func tlv188() ([]byte, error) {
	tlvData := []byte("\x4D\xBF\x65\x33\xD9\x08\xC2\x73\x63\x6D\xE5\xCD\xAE\x83\xC0\x43")
	return tlvPack(0x0188, tlvData, 0)
}

func tlv191() ([]byte, error) {
	tlvData := make([]byte, 1)
	return tlvPack(0x0191, tlvData, 0)
}

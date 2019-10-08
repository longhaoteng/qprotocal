package qprotocal

import (
	"bytes"
	"github.com/lunixbochs/struc"
)

type b struct {
	B uint `struc:"uint8"`
}

type h struct {
	H uint `struc:"uint16"`
}

type i struct {
	I uint `struc:"uint32"`
}

type l struct {
	L uint `struc:"uint32"`
}

func structPack(data interface{}) ([]byte, error) {
	var dataBuf bytes.Buffer
	err := struc.Pack(&dataBuf, data)
	if err != nil {
		return nil, err
	}
	return dataBuf.Bytes(), nil
}

func pack(qq *QQ, bin []byte, packType int) ([]byte, error) {
	packageData := make([]byte, 0)

	if packType == 0 {
		packageData = []byte("\x00\x00\x00\x08\x02\x00\x00\x00\x04")
	} else if packType == 1 {
		packageData = []byte("\x00\x00\x00\x08\x02\x00\x00")
		data1, err := structPack(&h{uint(len(qq.Token002c) + 4)})
		if err != nil {
			return nil, err
		}
		packageData = byteJoins(packageData, data1, qq.Token002c)
	} else {
		packageData = []byte("\x00\x00\x00\x09\x01")
		data2, err := structPack(&i{qq.RequestId})
		if err != nil {
			return nil, err
		}
		packageData = byteJoin(packageData, data2)
	}

	packageData = byteJoin(packageData, []byte("\x00\x00\x00"))

	data3, err := structPack(&h{uint(len(qq.Caption) + 4)})
	if err != nil {
		return nil, err
	}
	packageData = byteJoins(packageData, data3, []byte(qq.Caption), bin)

	data4, err := structPack(&i{uint(len(packageData) + 4)})
	if err != nil {
		return nil, err
	}
	packageData = byteJoin(data4, packageData)

	return packageData, nil
}

func unpack(qq *QQ, packageData []byte) []byte {
	pos1 := bytes.Index(packageData, []byte(qq.Caption))
	return packageData[pos1+len(qq.Caption):]
}

func unpackVerificationImg(qq *QQ, bin []byte) error {
	return tlvUnPack(qq, bin[3:])
}

func unpackErrorMsg(qq *QQ, bin []byte) error {
	bin = bin[9:]

	titleLen := &h{}
	err := struc.Unpack(bytes.NewBuffer(bin[4:6]), titleLen)
	if err != nil {
		return err
	}
	bin = bin[6:]
	title := string(bin[:titleLen.H])
	bin = bin[titleLen.H:]

	messageLen := &h{}
	err = struc.Unpack(bytes.NewBuffer(bin[:2]), messageLen)
	if err != nil {
		return err
	}
	bin = bin[2:]
	message := string(bin[:messageLen.H])
	qq.LastError = title + "。" + message

	return nil
}

func packLoginSsoMsg(qq *QQ, serviceCmd, wupBuffer, token []byte, isLogin int) ([]byte, error) {
	msgCookies := []byte("\xB6\xCC\x78\xFC")

	type Data struct {
		RequestId uint `struc:"uint32"`
		AppId1    uint `struc:"uint32"`
		AppId2    uint `struc:"uint32"`
		Ex1       uint `struc:"uint32"`
		Ex2       uint `struc:"uint32"`
		Ex3       uint `struc:"uint32"`
		TokenLen  uint `struc:"uint32"`
	}
	packageData, err := structPack(&Data{qq.RequestId, qq.AppId, qq.AppId, 0x01000000, 0, 0, uint(len(token) + 4)})
	if err != nil {
		return nil, err
	}

	packageData = byteJoin(packageData, token)

	data1, err := structPack(&i{uint(len(serviceCmd) + 4)})
	if err != nil {
		return nil, err
	}
	packageData = byteJoins(packageData, data1, serviceCmd)

	data2, err := structPack(&i{uint(len(msgCookies) + 4)})
	if err != nil {
		return nil, err
	}
	packageData = byteJoins(packageData, data2, msgCookies)

	data3, err := structPack(&i{uint(len(qq.Imei) + 4)})
	if err != nil {
		return nil, err
	}
	packageData = byteJoins(packageData, data3, qq.Imei)

	data4, err := structPack(&i{4})
	if err != nil {
		return nil, err
	}
	packageData = byteJoin(packageData, data4)

	data5, err := structPack(&h{uint(len(qq.ApkVer) + 2)})
	if err != nil {
		return nil, err
	}
	packageData = byteJoins(packageData, data5, qq.ApkVer)

	data6, err := structPack(&i{uint(len(packageData) + 4)})
	if err != nil {
		return nil, err
	}
	packageData = byteJoin(data6, packageData)

	data7, err := structPack(&i{uint(len(wupBuffer) + 4)})
	if err != nil {
		return nil, err
	}
	packageData = byteJoins(packageData, data7, wupBuffer)

	encrypted, err := encrypt(packageData, qq.SessionKey)
	if err != nil {
		return nil, err
	}

	packageData, err = pack(qq, encrypted, isLogin^0)
	if err != nil {
		return nil, err
	}

	return packageData, nil
}

func increasePcSubCmd(qq *QQ) {
	if qq.PcSubCmd > 2147483647 {
		qq.PcSubCmd = 10000
	} else {
		qq.PcSubCmd += 1
	}
}

func increaseSsoSeq(qq *QQ) {
	if qq.RequestId > 2147483647 {
		qq.RequestId = 10000
	} else {
		qq.RequestId += 1
	}
}

func packPackage(qq *QQ, tlvPackage []byte) ([]byte, error) {
	type Data struct {
		Ex       uint `struc:"uint16"`
		PcSubCmd uint `struc:"uint16"`
		Uin      uint `struc:"uint32"`
	}
	data1, err := structPack(&Data{0x0810, qq.PcSubCmd, qq.Uin})
	if err != nil {
		return nil, err
	}

	tlvData := byteJoins(qq.PcVer, data1, []byte("\x03\x07\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00"))

	pubKeyLen := len(qq.PubKey)

	if pubKeyLen > 0 {
		tlvData = byteJoin(tlvData, []byte("\x01\x01"))
	} else {
		tlvData = byteJoin(tlvData, []byte("\x01\x02"))
	}

	data2, err := structPack(&h{uint(pubKeyLen)})
	if err != nil {
		return nil, err
	}

	tlvData = byteJoins(tlvData, qq.RandKey, []byte("\x01\x02"), data2)

	if pubKeyLen > 0 {
		tlvData = byteJoin(tlvData, qq.PubKey)
	} else {
		data3, err := structPack(&h{0})
		if err != nil {
			return nil, err
		}
		tlvData = byteJoin(tlvData, data3)
	}

	bin, err := encrypt(tlvPackage, qq.ShareKey)

	tlvData = byteJoins(tlvData, bin, []byte("\x03"))

	data4, err := structPack(&h{uint(len(tlvData) + 3)})
	if err != nil {
		return nil, err
	}
	return byteJoins([]byte("\x02"), data4, tlvData), nil
}

func packTlv2(qq *QQ, code string) ([]byte, error) {
	tlv2, err := tlv2(code, qq.VerificationToken1)
	if err != nil {
		return nil, err
	}

	tlv8, err := tlv8()
	if err != nil {
		return nil, err
	}

	tlv104, err := tlv104(qq.VerificationToken2)
	if err != nil {
		return nil, err
	}

	tlv116, err := tlv116()
	if err != nil {
		return nil, err
	}

	cmd, err := structPack(&h{2})
	if err != nil {
		return nil, err
	}

	tlvNum, err := structPack(&h{4})
	if err != nil {
		return nil, err
	}

	return byteJoins(cmd, tlvNum, tlv2, tlv8, tlv104, tlv116), nil
}

func packTlv9(qq *QQ) ([]byte, error) {
	tlv18, err := tlv18(qq.Uin)
	if err != nil {
		return nil, err
	}

	tlv1, err := tlv1(qq.Uin, qq.Time)
	if err != nil {
		return nil, err
	}

	tlv106, err := tlv106(qq.Uin, qq.Md5Pwd, qq.Md5Pwd2, qq.TgtKey, qq.Imei, qq.Time, qq.AppId)
	if err != nil {
		return nil, err
	}

	tlv116, err := tlv116()
	if err != nil {
		return nil, err
	}

	tlv100, err := tlv100(qq.AppId)
	if err != nil {
		return nil, err
	}

	tlv108, err := tlv108(qq.KSid)
	if err != nil {
		return nil, err
	}

	tlv107, err := tlv107()
	if err != nil {
		return nil, err
	}

	tlv109, err := tlv109(qq.Imei)
	if err != nil {
		return nil, err
	}

	tlv124, err := tlv124(qq.OsType, qq.OsVersion, qq.Apn, qq.NetworkType)
	if err != nil {
		return nil, err
	}

	tlv128, err := tlv128(qq.Device, qq.Imei)
	if err != nil {
		return nil, err
	}

	tlv16e, err := tlv16e(qq.Device)
	if err != nil {
		return nil, err
	}

	tlv144, err := tlv144(qq.TgtKey, tlv109, tlv124, tlv128, tlv16e)
	if err != nil {
		return nil, err
	}

	tlv142, err := tlv142(qq.ApkId)
	if err != nil {
		return nil, err
	}

	tlv145, err := tlv145(qq.Imei)
	if err != nil {
		return nil, err
	}

	tlv154, err := tlv154(qq.RequestId)
	if err != nil {
		return nil, err
	}

	tlv141, err := tlv141(qq.NetworkType, qq.Apn)
	if err != nil {
		return nil, err
	}

	tlv8, err := tlv8()
	if err != nil {
		return nil, err
	}

	tlv16b, err := tlv16b()
	if err != nil {
		return nil, err
	}

	tlv147, err := tlv147(qq.ApkVer, qq.ApkSig)
	if err != nil {
		return nil, err
	}

	tlv177, err := tlv177()
	if err != nil {
		return nil, err
	}

	tlv187, err := tlv187()
	if err != nil {
		return nil, err
	}

	tlv188, err := tlv188()
	if err != nil {
		return nil, err
	}

	tlv191, err := tlv191()
	if err != nil {
		return nil, err
	}

	cmd, err := structPack(&h{9})
	if err != nil {
		return nil, err
	}

	tlvNum, err := structPack(&h{19})
	if err != nil {
		return nil, err
	}

	return byteJoins(
		cmd,
		tlvNum,
		tlv18,
		tlv1,
		tlv106,
		tlv116,
		tlv100,
		tlv108,
		tlv107,
		tlv144,
		tlv142,
		tlv145,
		tlv154,
		tlv141,
		tlv8,
		tlv16b,
		tlv147,
		tlv177,
		tlv187,
		tlv188,
		tlv191,
	), nil

}

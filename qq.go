package qprotocal

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/lunixbochs/struc"
	"net"
	"strconv"
	"time"
)

type QQ struct {
	// tcp
	Conn net.Conn

	Caption  string
	Uin      uint
	UinLong  []byte
	Password string
	Md5Pwd   []byte
	Md5Pwd2  []byte
	KSid     []byte

	Imei        []byte
	ApkVer      []byte
	ShareKey    []byte
	PubKey      []byte
	AppId       uint
	PcVer       []byte
	OsType      []byte
	OsVersion   []byte
	NetworkType uint
	Apn         []byte
	Device      []byte
	ApkId       []byte
	ApkSig      []byte
	Time        int64
	TgtKey      []byte
	RandKey     []byte
	Mst1Key     []byte
	StWeb       []byte

	// sso_seq
	RequestId uint
	PcSubCmd  uint

	// sessions
	Token002c  []byte
	Token004c  []byte
	Token0058  []byte
	SessionKey []byte

	// login state
	// 0 logining, 1 verify, 2 success
	LoginState uint
	LastError  string

	// account info
	Nick               string
	Face               uint
	Age                uint
	Gender             uint
	Key                []byte
	SKey               []byte
	VKey               []byte
	Sid                []byte
	Verification       []byte
	VerificationToken1 []byte
	VerificationToken2 []byte
	PsKey              []byte
	SuperKey           []byte
}

func (qq *QQ) send(data []byte) error {
	increaseSsoSeq(qq)

	_, err := qq.Conn.Write(data)
	return err
}

func (qq *QQ) recovery() ([]byte, error) {
	reply := make([]byte, 4096)
	n, err := qq.Conn.Read(reply)
	if e, ok := err.(interface{ Timeout() bool }); ok && e.Timeout() {
		qq.LastError = "连接服务器超时"
	} else if err != nil {
		return nil, err
	}
	return reply[:n], nil
}

func recoveryHandle(qq *QQ, data []byte) error {
	if len(data) == 0 {
		qq.LastError = "返回包为空"
	}

	bin := unpack(qq, data)

	bin, err := decrypt(bin, qq.SessionKey)
	if err != nil {
		return err
	}

	headLen := &l{}
	err = struc.Unpack(bytes.NewBuffer(bin[:4]), headLen)
	if err != nil {
		return err
	}

	// split data
	bodyBin := bin[headLen.L:]
	bin = bin[4:headLen.L]

	ssqSeq := &l{}
	err = struc.Unpack(bytes.NewBuffer(bin[:4]), ssqSeq)
	if err != nil {
		return err
	}

	bin = bin[4:]

	if bytes.Equal(bin[:4], make([]byte, 4)) {
		bin = bin[8:]
	} else {
		bin = bin[4:]

		fooLen := &l{}
		err = struc.Unpack(bytes.NewBuffer(bin[:4]), fooLen)
		if err != nil {
			return err
		}

		bin = bin[4:]
		bin = bin[:fooLen.L-4]
	}

	fooLen := &l{}
	err = struc.Unpack(bytes.NewBuffer(bin[:4]), fooLen)
	if err != nil {
		return err
	}

	serviceCmd := string(bin[4:fooLen.L][:])

	return msgHandle(qq, serviceCmd, bodyBin)
}

func msgHandle(qq *QQ, serviceCmd string, bodyBin []byte) error {
	if serviceCmd == "wtlogin.login" {
		bin := bodyBin[4:]

		fooLen := &h{}
		err := struc.Unpack(bytes.NewBuffer(bin[1:3]), fooLen)
		if err != nil {
			return err
		}

		result := &b{}
		err = struc.Unpack(bytes.NewBuffer(bin[15:16]), result)
		if err != nil {
			return err
		}

		bin = bin[16:]
		bin = bin[:fooLen.H-17]
		bin, err = decrypt(bin, qq.ShareKey)
		if err != nil {
			return err
		}

		if result.B != 0 {
			if result.B == 2 {
				err := unpackVerificationImg(qq, bin)
				if err != nil {
					return err
				}
				qq.LastError = "需要输入验证码"
				qq.LoginState = 1
				bin = nil
			} else {
				err := unpackErrorMsg(qq, bin)
				if err != nil {
					return err
				}
				qq.LoginState = 0
				bin = nil
			}
		}

		if bin == nil {
			return nil
		}

		bin = bin[7:]

		binLen := &h{}
		err = struc.Unpack(bytes.NewBuffer(bin[:2]), binLen)
		if err != nil {
			return err
		}

		bin = bin[2:]
		bin = bin[:binLen.H]
		bin, err = decrypt(bin, qq.TgtKey)
		if err != nil {
			return err
		}
		err = tlvUnPack(qq, bin)
		if err != nil {
			return err
		}
		qq.Key = qq.SessionKey
		qq.LoginState = 2
	} else if serviceCmd == "OidbSvc.0x7a2_0" {
	} else if serviceCmd == "friendlist.getFriendGroupList" {
	} else if serviceCmd == "EncounterSvc.ReqGetEncounter" {
	} else if serviceCmd == "friendlist.getUserAddFriendSetting" {
	} else if serviceCmd == "SummaryCard.ReqCondSearch" {
	} else if serviceCmd == "friendlist.GetAutoInfoReq" {
	} else if serviceCmd == "SQQzoneSvc.getMainPage" {
	} else if serviceCmd == "friendlist.addFriend" {
	} else if serviceCmd == "ProfileService.GroupMngReq" {
	} else if serviceCmd == "OnlinePush.PbPushGroupMsg" {
	} else if serviceCmd == "MessageSvc.PushReaded" {
	} else if serviceCmd == "MessageSvc.PushNotify" {
	} else if serviceCmd == "StatSvc.get" {
	} else if serviceCmd == "SummaryCard.ReqSummaryCard" {
	} else if serviceCmd == "ConfigPushSvc.PushReq" {
	} else if serviceCmd == "OidbSvc.0x4ff_9" {
	} else if serviceCmd == "QQServiceDiscussSvc.ReqGetDiscuss" {
	} else if serviceCmd == "account.RequestReBindMobile" {
	} else if serviceCmd == "Signature.auth" {
	} else if serviceCmd == "SQQzoneSvc.publishmess" {
	} else if serviceCmd == "VisitorSvc.ReqFavorite" {
	} else if serviceCmd == "friendlist.GetSimpleOnlineFriendInfoReq" {
	} else if serviceCmd == "FriendList.GetTroopListReqV2" {
	} else if serviceCmd == "friendlist.getTroopMemberList" {
	} else if serviceCmd == "QQServiceDiscussSvc.ReqCreateDiscuss" {
	} else if serviceCmd == "QQServiceDiscussSvc.ReqAddDiscussMember" {
	} else if serviceCmd == "SQQzoneSvc.getApplist" {
	} else if serviceCmd == "friendlist.GetSimpleOnlineFriendInfoReq" {
	} else if serviceCmd == "friendlist.GetSimpleOnlineFriendInfoReq" {
	}
	return nil
}

func loginHandle(qq *QQ, tlvPackage []byte) error {
	wupBuffer, err := packPackage(qq, tlvPackage)
	if err != nil {
		return err
	}

	data, err := packLoginSsoMsg(qq, []byte("wtlogin.login"), wupBuffer, []byte(""), 1)
	if err != nil {
		return err
	}

	err = qq.send(data)
	if err != nil {
		return err
	}

	recvData, err := qq.recovery()
	if err != nil {
		return err
	}
	err = recoveryHandle(qq, recvData)
	if err != nil {
		return err
	}

	return nil
}

func Init(uin, password string) (*QQ, error) {
	qq := &QQ{}

	qq.Caption = uin
	uinInt, err := strconv.Atoi(uin)
	if err != nil {
		return nil, err
	}
	qq.Uin = uint(uinInt)

	uinLong, err := structPack(&i{qq.Uin})
	if err != nil {
		return nil, err
	}
	qq.UinLong = uinLong
	qq.Password = password
	qq.Md5Pwd = getMd5Value([]byte(qq.Password))
	data1, err := hex.DecodeString(fmt.Sprintf("%x", qq.Uin))
	if err != nil {
		return nil, err
	}
	qq.Md5Pwd2 = getMd5Value(byteJoins(qq.Md5Pwd, make([]byte, 4), data1))
	data2, err := hex.DecodeString("93AC689396D57E5F9496B81536AAFE91")
	if err != nil {
		return nil, err
	}
	qq.KSid = data2
	qq.Imei = []byte("866819027236657")
	qq.ApkVer = []byte("5.8.0.157158")
	data3, err := hex.DecodeString("957C3AAFBF6FAF1D2C2F19A5EA04E51C")
	if err != nil {
		return nil, err
	}
	qq.ShareKey = data3
	data4, err := hex.DecodeString("02244B79F2239755E73C73FF583D4EC5625C19BF8095446DE1")
	if err != nil {
		return nil, err
	}
	qq.PubKey = data4
	qq.AppId = 537042771
	qq.PcVer = []byte("\x1F\x41")
	qq.OsType = []byte("android")
	qq.OsVersion = []byte("4.4.4")
	qq.NetworkType = 2
	qq.Apn = []byte("wifi")
	qq.Device = []byte("Nexus 5")
	qq.ApkId = []byte("com.tencent.mobileqq")
	qq.ApkSig = []byte("\xA6\xB7\x45\xBF\x24\xA2\xC2\x77\x52\x77\x16\xF6\xF3\x6E\xB6\x8D")
	qq.Time = time.Now().UnixNano()
	data5, err := getRandomHex(16)
	if err != nil {
		return nil, err
	}
	qq.TgtKey = data5
	data6, err := getRandomHex(16)
	if err != nil {
		return nil, err
	}
	qq.RandKey = data6

	qq.RequestId = 10000
	qq.PcSubCmd = 0

	qq.SessionKey = make([]byte, 16)

	qq.LoginState = 0

	qq.Conn, err = net.Dial("tcp", "msfwifi.3g.qq.com:8080")
	if err != nil {
		return nil, err
	}

	return qq, nil
}

func (qq *QQ) Login() error {
	tlvPackage, err := packTlv9(qq)
	if err != nil {
		return err
	}

	// first login
	increasePcSubCmd(qq)

	return loginHandle(qq, tlvPackage)
}

func (qq *QQ) SendCode(code string) error {
	tlvPackage, err := packTlv2(qq, code)
	if err != nil {
		return err
	}

	return loginHandle(qq, tlvPackage)
}

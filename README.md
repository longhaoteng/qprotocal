# qprotocal
安卓qq协议golang库

### Install
```go get github.com/longhaoteng/qprotocal```

### Usage
```go
import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	qq "github.com/longhaoteng/qprotocal"
)

func main() {
	q, err := qq.Init("1151018295", "123456")
	if err != nil {
		log.Fatal(err)
	}
	err = q.Login()
	if err != nil {
		log.Fatal(err)
	}

	if q.LoginState == 0 {
		log.Println(q.LastError)
	} else if q.LoginState == 1 {
		out, err := os.Create("./verification_code.jpg")
		if err != nil {
			log.Fatal(err)
		}
		defer out.Close()
		for {
			code := ""
			_, err = io.Copy(out, bytes.NewReader(q.Verification))
			log.Printf("verification code img path：%s", out.Name())
			log.Printf("%s：", q.LastError)
			_, _ = fmt.Scanln(&code)
			err := q.SendCode(code)
			if err != nil {
				log.Fatal(err)
			}
			if q.LoginState != 1 {
				break
			}
		}
	} else {
		log.Printf("nick：%s", q.Nick)
		log.Printf("face：%d", q.Face)
		log.Printf("age：%d", q.Age)
		log.Printf("gender：%d", q.Gender)
		log.Printf("token002c：%s", hex.EncodeToString(q.Token002c))
		log.Printf("token004c：%s", hex.EncodeToString(q.Token004c))
		log.Printf("sessionKey：%s", hex.EncodeToString(q.SessionKey))
	}
}
```

### 声明
使用本项目代码产生的任何后果与本人无关。

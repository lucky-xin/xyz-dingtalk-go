package dingtalk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/lucky-xin/xyz-common-go/log"
	"github.com/lucky-xin/xyz-dingtalk-go/domain"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	"net/http"
	"strconv"
	"time"
	"unsafe"
)

type SignConf struct {
	// AccessToken
	AccessToken string `json:"token" validate:"required"`
	// Secret
	Secret string `json:"secret" validate:"required"`
}

type RobotV1 struct {
	Signs []*SignConf
}

type RobotV2 struct {
}

func NewRobot(confs ...*SignConf) (robot *RobotV1) {
	robot = &RobotV1{Signs: confs}
	return
}

func NewSignConf(token, secret string) *SignConf {
	return &SignConf{AccessToken: token, Secret: secret}
}

type marshal func(req *domain.MsgExchange) ([]byte, error)

var convertMapper = map[domain.MsgType]marshal{
	domain.MsgType_text: func(req *domain.MsgExchange) ([]byte, error) {
		val := req.GetTextMsg()
		val.Msgtype = domain.MsgType_text.String()
		return protojson.Marshal(val)
	},
	domain.MsgType_link: func(req *domain.MsgExchange) ([]byte, error) {
		val := req.GetLinkMsg()
		val.Msgtype = domain.MsgType_link.String()
		return protojson.Marshal(val)
	},
	domain.MsgType_markdown: func(req *domain.MsgExchange) ([]byte, error) {
		val := req.GetMarkdownMsg()
		val.Msgtype = domain.MsgType_markdown.String()
		return protojson.Marshal(val)
	},
	domain.MsgType_feedCard: func(req *domain.MsgExchange) ([]byte, error) {
		val := req.GetFeedCardMsg()
		val.Msgtype = domain.MsgType_feedCard.String()
		return protojson.Marshal(val)
	},
	domain.MsgType_actionCard: func(req *domain.MsgExchange) ([]byte, error) {
		val := req.GetActionCardMsg()
		val.Msgtype = domain.MsgType_actionCard.String()
		return protojson.Marshal(val)
	},
}

func (robot *RobotV1) SendMsg(req *domain.MsgExchange) (err error) {
	for _, conf := range robot.Signs {
		req.Token = conf.AccessToken
		req.Secret = conf.Secret
		err := SendMsg(req)
		if err != nil {
			return err
		}
	}
	return
}

func SendMsg(req *domain.MsgExchange) (err error) {
	converter := convertMapper[req.Msgtype]
	if converter == nil {
		return errors.New("invalid message type")
	}
	marshal, err := converter(req)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(marshal)
	// 发送请求
	if resp, err := http.Post(signUrl(req.Token, req.Secret), "application/json;charset=UTF-8", reader); err != nil {
		return err
	} else {
		respBytes, err1 := io.ReadAll(resp.Body)
		if err1 != nil {
			return err1
		}
		//byte数组直接转成string，优化内存
		str := (*string)(unsafe.Pointer(&respBytes))
		log.Logger.Info(str)
	}

	return
}

// signUrl 加签
func signUrl(token, secret string) string {
	webHookUrl := "https://oapi.dingtalk.com/robot/send?access_token=" + string(token)
	// 获取当前秒级时间戳
	timestamp := time.Now()
	milliTimestamp := timestamp.UnixNano() / 1e6
	stringToSign := fmt.Sprintf("%s\n%s", strconv.Itoa(int(milliTimestamp)), secret)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	hookUrl := fmt.Sprintf("%s&timestamp=%s&sign=%s", webHookUrl, strconv.Itoa(int(milliTimestamp)), sign)
	return hookUrl
}

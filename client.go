package netease

import (
	"strconv"
	"sync"
	"time"

	"crypto/sha1"

	jsoniter "github.com/json-iterator/go"
	"github.com/spf13/cast"
	"gopkg.in/resty.v1"
)

var jsonTool = jsoniter.ConfigCompatibleWithStandardLibrary

// public $AppKey;                //开发者平台分配的AppKey
// public $AppSecret;             //开发者平台分配的AppSecret,可刷新
// public $Nonce;                    //随机数（最大长度128个字符）
// public $CurTime;                 //当前UTC时间戳，从1970年1月1日0点0 分0 秒开始到现在的秒数(String)
// public $CheckSum;                //SHA1(AppSecret + Nonce + CurTime),三个参数拼接的字符串，进行SHA1哈希计算，转化成16进制字符(String，小写)

//ImClient .
type ImClient struct {
	AppKey    string
	AppSecret string
	Nonce     string
	CurTime   string
	CheckSum  string

	mutex  *sync.Mutex
	client *resty.Client
}

//CreateImClient  创建im客户端，proxy留空表示不使用代理
func CreateImClient(appkey, appSecret, httpProxy string) *ImClient {
	curTime := cast.ToString(time.Now())
	nonCe := RandStringBytesMaskImprSrc(64)
	s := appSecret + nonCe + curTime
	h := sha1.New()
	h.Write([]byte(s))
	checkSum := h.Sum(nil)
	c := &ImClient{AppKey: appkey, AppSecret: appSecret, Nonce: nonCe, CurTime: curTime, CheckSum: string(checkSum), mutex: new(sync.Mutex)}
	c.client = resty.New()
	if len(httpProxy) > 0 {
		c.client.SetProxy(httpProxy)
	}

	// c.client.SetHeader("Accept", "application/json;charset=utf-8")
	c.client.SetHeader("Content-Type", "application/x-www-form-urlencoded;charset=utf-8;")
	c.client.SetHeader("AppKey", c.AppKey)
	c.client.SetHeader("Nonce", c.Nonce)
	c.client.SetHeader("CurTime", c.CurTime)
	c.client.SetHeader("CheckSum", c.CheckSum)

	return c
}

func (c *ImClient) setCommonHead(req *resty.Request) {
	c.mutex.Lock() //多线程并发访问map导致panic
	defer c.mutex.Unlock()

	timeStamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.SetHeader("CurTime", timeStamp)
	req.SetHeader("CheckSum", ShaHashToHexStringFromString(c.AppSecret+c.Nonce+timeStamp))
}

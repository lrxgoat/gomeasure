/*
	代码对域名的TLS/HTTPS安全进行测量，包括TLS版本、证书、CT、证书撤销以及TLS降级攻击。
	在go.mod的添加：
		replace github.com/Sirupsen/logrus v1.8.1 => github.com/sirupsen/logrus v1.8.1

	输入为(ip,domain)格式的文件, 参数依次为进程数量, 输入文件, 输出文件夹。
	ex: go run scan.go 100 ./input.txt ./result/
	输出为四个json文件，分别为TLSResult, CertResult, CTResult, RevokeResult 结构体
*/


package main

import (
	"bufio"
	_ "bytes"
	_ "crypto"
	_"crypto/tls"
	_ "crypto/x509"
	_ "encoding/asn1"
	_ "encoding/base64"
	_ "encoding/json"
	_ "encoding/pem"
	_ "errors"
	"flag"
	"fmt"
	_ "github.com/certifi/gocertifi"
	_ "github.com/tumi8/tls"
	_ "github.com/zzylydx/Zgoscanner/scanner"
	_ "github.com/zzylydx/Zsct"
	_ "github.com/zzylydx/zcrypto/x509/revocation/ocsp"
	_ "golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	_ "io/ioutil"
	_ "net"
	_ "net/http"
	"os"
	"runtime"
	"strconv"
	_ "strings"
	"sync"
	"time"
)


func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	//cipherSuites = scanner.ReadCiphersFromAsset()
}

func main() {

	var numThreads = flag.Int("t",100,"Number of threads")
	var QPS = flag.Int("q",100,"Number of QPS")
	var inputFile = flag.String("i","./input","Input File")
	var resultpath =  flag.String("o","./result","Output File")
	var port = flag.Int("p",443,"Scan Port")
	var sni = flag.Bool("sni",true,"Whether to specify SNI")

	startTime := time.Now()
	fmt.Println("start scan at:", startTime)

	flag.Parse()
	fmt.Println(*sni)
	//args := os.Args[1:]
	//numThreads, _ := strconv.Atoi(args[0]) // 进程数量
	//inputFile := args[1]                   // 输入文件
	//resultpath := args[2]                  // 输出文件夹路径

	//QPS := 400                              // 令牌桶算法，往桶里面放令牌的速度，可以理解为每秒的发包数量，根据带宽大小设定
	jobs := make(chan string)
	var wg sync.WaitGroup
	limiter := rate.NewLimiter(rate.Limit(*QPS), 1)
	ctx := context.Background()
	// 创建进程
	for w := 0; w < *numThreads; w++ {
		go func(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, i int, ctxScoped context.Context) {
			wgScoped.Add(1)
			// 四个输出文件
			TLSFile := *resultpath + "tls-" + strconv.Itoa(i) + ".txt"
			CertFile := *resultpath + "cert-" + strconv.Itoa(i) + ".txt"
			CTFile := *resultpath + "ct-" + strconv.Itoa(i) + ".txt"
			RevokeFile := *resultpath + "revoke-" + strconv.Itoa(i) + ".txt"
			// 开始扫描
			start(jobs, TLSFile, CertFile, CTFile, RevokeFile, *port, *sni, wgScoped, limiterScoped, ctxScoped)
		}(&wg, limiter, w, ctx)
	}
	// 读取输入文件
	inputf, err := os.Open(*inputFile)
	if err != nil {
		err.Error()
	}
	scanner := bufio.NewScanner(inputf)
	// 将输入写入通道
	for scanner.Scan() {
		jobs <- scanner.Text()
	}
	close(jobs)
	wg.Wait()

	inputf.Close()

	endTime := time.Now()
	fmt.Println("end scan at:", endTime)
	fmt.Println("duration:", time.Since(startTime).String())
}

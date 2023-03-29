package main

import (
	"errors"
	"fmt"
	"os"
	"sync"

	fp "path/filepath"
	str "strings"

	"sectest/ffuf"
)

func (t *targetT) ffufCommon(host, scan string, pi portInfoT, wg *sync.WaitGroup) {
	var c cmdT
	c.name = fmt.Sprintf("common_%s_%d", scan, pi.port)
	c.bin = "ffuf"

	wordlist := "./data/http_common_" + scan

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	f := "-se -noninteractive -r -t 64 -r -o %s/ffuf/common_%s.json "
	f += "-w %s:FUZZ -u http%s://%s:%d/FUZZ"
	argsS := fmt.Sprintf(f, t.host, scan, wordlist, sslSuffix, host, pi.port)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-H")
	c.args = append(c.args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	runCmd(host, &c)
	err := ffuf.CleanFfuf(fp.Join(host, c.bin, c.name))
	errExit(err)

	wg.Done()
}

// l - recursion level
func (t *targetT) ffufRec(host, scan, l string, pi portInfoT, wg *sync.WaitGroup) {
	file := fmt.Sprintf("%s/ffuf/common_%s.json", t.host, scan)
	ffufRes, err := ffuf.GetUrls(file)
	errExit(err)

	err = ffuf.GetDirs(ffufRes, t.host, scan, l, "data/http_dir")
	errExit(err)

	var c cmdT
	c.name = fmt.Sprintf("rec_%s_%d_l%s", scan, pi.port, l)
	c.bin = "ffuf"

	dirlist := fp.Join(host, "tmp", "ffuf_rec_"+scan+"_l"+l)
	filelist := "./data/http_file_rec_" + scan

	_, err = os.Stat(dirlist)
	if errors.Is(err, os.ErrNotExist) {
		wg.Done()
		return
	}

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	f := "-se -noninteractive -r -t 64 -r -o %s/ffuf/rec_%s_l%s.json "
	f += "-fc 401,403 "
	f += "-w %s:DIR -w %s:FILE -u http%s://%s:%d/DIR/FILE"
	argsS := fmt.Sprintf(f, t.host, scan, l, dirlist, filelist,
		sslSuffix, host, pi.port)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-H")
	c.args = append(c.args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	runCmd(host, &c)
	err = ffuf.CleanFfuf(fp.Join(host, c.bin, c.name))
	errExit(err)

	wg.Done()
}

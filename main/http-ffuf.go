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

func (t *targetT) ffufUrlEnum(host string, pi portInfoT, wg *sync.WaitGroup) {
	var c cmdT
	c.name = fmt.Sprintf("url_enum_%s", host)
	c.bin = "ffuf"

	wordlist := "./data/http_url_enum"

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	formatS := "-se -noninteractive -r -t 64 -r -o %s/%d/%s.json "
	formatS += "-w %s:FUZZ -u http%s://%s:%d/FUZZ"
	argsS := fmt.Sprintf(formatS,
		t.host, pi.port, c.name, wordlist, sslSuffix, host, pi.port)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-H")
	c.args = append(c.args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	runCmd(host, pi.portS, &c)
	err := ffuf.CleanFfuf(fp.Join(t.host, pi.portS, c.name))
	errExit(err)

	wg.Done()
}

// l - recursion level
func (t *targetT) ffufUrlEnumRec(host, l string, pi portInfoT, wg *sync.WaitGroup) {
	// read input from ffufUrlEnum
	file := fmt.Sprintf("%s/%d/url_enum_%s.json", t.host, pi.port, host)
	ffufRes, err := ffuf.GetUrls(file)
	errExit(err)

	dirlist := fmt.Sprintf("%s/%d/url_enum_rec_l%s_%s.json",
		t.host, pi.port, l, host)
	err = ffuf.GetDirs(ffufRes, t.host, l, "data/http_dir", dirlist)
	errExit(err)

	var c cmdT
	c.name = fmt.Sprintf("url_enum_%s_rec_l%s", host, l)
	c.bin = "ffuf"

	filelist := "./data/http_url_enum_rec_file"

	_, err = os.Stat(dirlist)
	if errors.Is(err, os.ErrNotExist) {
		wg.Done()
		return
	}

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	formatS := "-se -noninteractive -r -t 64 -r -o %s/%d/%s.json "
	formatS += "-fc 401,403 "
	formatS += "-w %s:DIR -w %s:FILE -u http%s://%s:%d/DIR/FILE"
	argsS := fmt.Sprintf(formatS, t.host, pi.port, c.name, dirlist,
		filelist, sslSuffix, host, pi.port)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-H")
	c.args = append(c.args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	runCmd(host, pi.portS, &c)
	err = ffuf.CleanFfuf(fp.Join(t.host, pi.portS, c.name))
	errExit(err)

	wg.Done()
}

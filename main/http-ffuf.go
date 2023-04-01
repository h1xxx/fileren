package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"

	fp "path/filepath"
	str "strings"

	"sectest/ffuf"
	"sectest/html"
)

func (t *targetT) ffufUrlEnum(host string, pi *portInfoT, wg *sync.WaitGroup) {
	var c cmdT
	c.name = fmt.Sprintf("url_enum_%s", host)
	c.bin = "ffuf"

	wordlist := "./data/http_url_enum"

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	formatS := "-se -noninteractive -r -t 64 -r -o %s/%s/%s.json "
	formatS += "-w %s:FUZZ -u http%s://%s:%d/FUZZ"
	argsS := fmt.Sprintf(formatS,
		t.host, pi.portS, c.name, wordlist, sslSuffix, host, pi.port)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-H")
	c.args = append(c.args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	runCmd(host, pi.portS, &c)
	err := ffuf.CleanFfuf(fp.Join(t.host, pi.portS, c.name+".out"))
	errExit(err)

	wg.Done()
}

// l - recursion level
func (t *targetT) ffufUrlEnumRec(host, l string, pi *portInfoT, wg *sync.WaitGroup) {
	// read input from ffufUrlEnum
	file := fmt.Sprintf("%s/%s/url_enum_%s.json", t.host, pi.portS, host)
	ffufRes, err := ffuf.GetResults(file)
	errExit(err)

	dirlist := fmt.Sprintf("%s/%s/url_enum_rec_l%s_%s.dirs",
		t.host, pi.portS, l, host)
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

	formatS := "-se -noninteractive -r -t 64 -r -o %s/%s/%s.json "
	formatS += "-fc 401,403 "
	formatS += "-w %s:DIR -w %s:FILE -u http%s://%s:%d/DIR/FILE"
	argsS := fmt.Sprintf(formatS, t.host, pi.portS, c.name, dirlist,
		filelist, sslSuffix, host, pi.port)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-H")
	c.args = append(c.args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	runCmd(host, pi.portS, &c)
	err = ffuf.CleanFfuf(fp.Join(t.host, pi.portS, c.name+".out"))
	errExit(err)

	wg.Done()
}

func (t *targetT) ffufLogin(host string, pi *portInfoT, form html.LoginParamsT) {
	var c cmdT
	c.name = fmt.Sprintf("weblogin_%s_%s", form.Action, host)
	c.bin = "ffuf"

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	errRespSize := 696969696969696969
	jsonOut := fmt.Sprintf("%s/%s/%s.json", t.host, pi.portS, c.name)

	formatS := "-se -noninteractive -r -t 64 -r -o %s "
	formatS += "-w data/ffuf_testlist:USER -w data/ffuf_testlist:PASS "
	formatS += "-u http%s://%s:%d/%s "
	formatS += "-X POST -d %s=USER&%s=PASS -fs %d"
	argsS := fmt.Sprintf(formatS, jsonOut,
		sslSuffix, host, pi.port, form.Action,
		form.Login, form.Pass, errRespSize)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-H")
	c.args = append(c.args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	c.args = append(c.args, "-H")
	c.args = append(c.args, "Content-Type: application/x-www-form-urlencoded")

	// test what is the actual response size to filter out errors
	cmd := exec.Command(c.bin, c.args...)
	err := cmd.Run()
	errExit(err)

	errRespSize, err = ffuf.GetRespSize(jsonOut)
	if err != nil {
		print("ffuf weblogin: can't determine response size, skipping")
		return
	}

	// replace test arguments with final values
	for i, v := range c.args {
		switch v {
		case "696969696969696969":
			c.args[i] = fmt.Sprintf("%d", errRespSize)
		case "data/ffuf_testlist:USER":
			c.args[i] = "data/weblogin_user:USER"
		case "data/ffuf_testlist:PASS":
			c.args[i] = "data/weblogin_pass:PASS"
		}
	}

	runCmd(host, pi.portS, &c)
	err = ffuf.CleanFfuf(fp.Join(t.host, pi.portS, c.name+".out"))
	errExit(err)
}

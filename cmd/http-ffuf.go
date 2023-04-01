package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"

	str "strings"

	"sectest/ffuf"
	"sectest/html"
)

func (t *targetT) ffufUrlEnum(host string, pi *portInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("url_enum_%s_%d", host, pi.port)
	c := t.prepareCmd(cname, "ffuf", pi.portS, []string{})

	wordlist := "./data/http_url_enum"

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	formatS := "-se -noninteractive -r -t 64 -r -o %s "
	formatS += "-w %s:FUZZ -u http%s://%s:%d/FUZZ"
	argsS := fmt.Sprintf(formatS, c.jsonOut,
		wordlist, sslSuffix, host, pi.port)

	args := str.Split(argsS, " ")

	args = append(args, "-H")
	args = append(args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	c = t.prepareCmd(cname, "ffuf", pi.portS, args)
	t.runCmd(c)

	err := ffuf.CleanFfuf(c.fileOut)
	if err != nil {
		msg := "error in %s: can't get clean ffuf output - %v\n"
		print(msg, c.name, err)
	}

	wg.Done()
}

// l - recursion level
func (t *targetT) ffufUrlEnumRec(host, l string, pi *portInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("url_enum_rec_l%s_%s_%d", l, host, pi.port)
	c := t.prepareCmd(cname, "ffuf", pi.portS, []string{})

	// read input from ffufUrlEnum
	file := fmt.Sprintf("%s/%s/url_enum_%s_%d.json",
		t.host, pi.portS, host, pi.port)
	ffufRes, err := ffuf.GetResults(file)
	if err != nil {
		msg := "error in %s: can't get ffuf results - %v\n"
		print(msg, c.name, err)
	}

	filelist := "./data/http_url_enum_rec_file"
	dirlist := fmt.Sprintf("%s/%s/url_enum_rec_l%s_%s_%d.dirs",
		t.host, pi.portS, l, host, pi.port)
	err = ffuf.GetDirs(ffufRes, t.host, l, "data/http_dir", dirlist)
	errExit(err)

	_, err = os.Stat(dirlist)
	if errors.Is(err, os.ErrNotExist) {
		wg.Done()
		return
	}

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	formatS := "-se -noninteractive -r -t 64 -r -o %s "
	formatS += "-fc 401,403 "
	formatS += "-w %s:DIR -w %s:FILE -u http%s://%s:%d/DIR/FILE"
	argsS := fmt.Sprintf(formatS, c.jsonOut,
		dirlist, filelist, sslSuffix, host, pi.port)

	args := str.Split(argsS, " ")

	args = append(args, "-H")
	args = append(args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	c = t.prepareCmd(cname, "ffuf", pi.portS, args)
	t.runCmd(c)

	err = ffuf.CleanFfuf(c.fileOut)
	if err != nil {
		msg := "error in %s: can't get clean ffuf output - %v\n"
		print(msg, c.name, err)
	}

	wg.Done()
}

func (t *targetT) ffufLogin(host string, pi *portInfoT, form html.LoginParamsT) {
	cname := fmt.Sprintf("weblogin_%s_%s_%d",
		str.Replace(form.Action, "/", "-", -1), host, pi.port)

	c := t.prepareCmd(cname, "ffuf", pi.portS, []string{})

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	errRespSize := 696969696969696969

	formatS := "-se -noninteractive -r -t 64 -r -o %s "
	formatS += "-w data/ffuf_testlist:USER -w data/ffuf_testlist:PASS "
	formatS += "-u http%s://%s:%d/%s "
	formatS += "-X POST -d %s=USER&%s=PASS -fs %d"
	argsS := fmt.Sprintf(formatS, c.jsonOut,
		sslSuffix, host, pi.port, form.Action,
		form.Login, form.Pass, errRespSize)

	args := str.Split(argsS, " ")

	args = append(args, "-H")
	args = append(args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	args = append(args, "-H")
	args = append(args, "Content-Type: application/x-www-form-urlencoded")

	// test what is the actual response size to filter out errors
	if !cmdIsDone(c.fileOut) {
		cmd := exec.Command(c.bin, args...)
		err := cmd.Run()
		if err != nil {
			msg := "error in %s: can't probe resp size - %v\n"
			print(msg, c.name, err)
		}

		errRespSize, err = ffuf.GetRespSize(c.jsonOut)
		if err != nil {
			print("ffuf weblogin: can't get resp size, skipping\n")
			return
		}
	}

	// replace test arguments with final values
	for i, v := range args {
		switch v {
		case "696969696969696969":
			args[i] = fmt.Sprintf("%d", errRespSize)
		case "data/ffuf_testlist:USER":
			args[i] = "data/weblogin_user:USER"
		case "data/ffuf_testlist:PASS":
			args[i] = "data/weblogin_pass:PASS"
		}
	}

	c = t.prepareCmd(cname, "ffuf", pi.portS, args)
	t.runCmd(c)

	err := ffuf.CleanFfuf(c.fileOut)
	if err != nil {
		msg := "error in %s: can't get clean ffuf output - %v\n"
		print(msg, c.name, err)
	}
}

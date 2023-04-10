package sectest

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"

	str "strings"

	"sectest/ffuf"
	"sectest/html"
)

func (t *TargetT) ffufUrlEnum(host string, pi *PortInfoT, creds *CredsT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("url_enum_%s_%d", host, pi.Port)
	if creds != nil {
		cname += "_" + creds.user
	}

	// init cmd prepare to set the file/dir locations
	c := t.prepareCmd(cname, "ffuf", pi.PortS, []string{})

	wordlist := "./data/http_url_enum"

	var sslSuffix string
	if pi.Tunnel == "ssl" {
		sslSuffix = "s"
	}

	formatS := "-se -noninteractive -r -t 60 -r -o %s "
	formatS += "-w %s:FUZZ -u http%s://%s:%d/FUZZ"
	argsS := fmt.Sprintf(formatS, c.jsonOut,
		wordlist, sslSuffix, host, pi.Port)

	args := str.Split(argsS, " ")

	args = append(args, "-H")
	args = append(args, fmt.Sprintf("User-Agent: %s", getRandomUA()))
	if creds != nil {
		args = append(args, "-H")
		args = append(args, "cookie: "+creds.cookie)
	}

	c = t.prepareCmd(cname, "ffuf", pi.PortS, args)
	t.runCmd(c)

	err := ffuf.CleanFfuf(c.fileOut)
	if err != nil {
		msg := "error in %s: can't get clean ffuf output - %v\n"
		Print(msg, c.name, err)
	}

	wg.Done()
}

// l - recursion level
func (t *TargetT) ffufUrlEnumRec(host, l string, pi *PortInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("url_enum_rec_l%s_%s_%d", l, host, pi.Port)

	// init cmd prepare to set the file/dir locations
	c := t.prepareCmd(cname, "ffuf", pi.PortS, []string{})

	// read input from ffufUrlEnum
	file := fmt.Sprintf("%s/%s/url_enum_%s_%d.json",
		t.Host, pi.PortS, host, pi.Port)
	ffufRes, _, err := ffuf.GetResults(file)
	if err != nil {
		msg := "error in %s: can't get ffuf results - %v\n"
		Print(msg, c.name, err)
	}

	filelist := "./data/http_url_enum_rec_file"
	dirlist := fmt.Sprintf("%s/%s/url_enum_rec_l%s_%s_%d.dirs",
		t.Host, pi.PortS, l, host, pi.Port)
	err = ffuf.GetDirs(ffufRes, t.Host, l, "data/http_dir", dirlist)
	errExit(err)

	_, err = os.Stat(dirlist)
	if errors.Is(err, os.ErrNotExist) {
		wg.Done()
		return
	}

	var sslSuffix string
	if pi.Tunnel == "ssl" {
		sslSuffix = "s"
	}

	formatS := "-se -noninteractive -r -t 60 -r -o %s "
	formatS += "-fc 401,403 "
	formatS += "-w %s:DIR -w %s:FILE -u http%s://%s:%d/DIR/FILE"
	argsS := fmt.Sprintf(formatS, c.jsonOut,
		dirlist, filelist, sslSuffix, host, pi.Port)

	args := str.Split(argsS, " ")

	args = append(args, "-H")
	args = append(args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	c = t.prepareCmd(cname, "ffuf", pi.PortS, args)
	t.runCmd(c)

	err = ffuf.CleanFfuf(c.fileOut)
	if err != nil {
		msg := "error in %s: can't get clean ffuf output - %v\n"
		Print(msg, c.name, err)
	}

	wg.Done()
}

func (t *TargetT) ffufLogin(host string, pi *PortInfoT, form html.LoginParamsT) {
	cname := fmt.Sprintf("weblogin_%s_%s_%d",
		str.Replace(form.Action, "/", "-", -1), host, pi.Port)

	// init cmd prepare to set the file/dir locations
	c := t.prepareCmd(cname, "ffuf", pi.PortS, []string{})

	var sslSuffix string
	if pi.Tunnel == "ssl" {
		sslSuffix = "s"
	}
	targetUrl := fmt.Sprintf("http%s://%s:%d/%s",
		sslSuffix, host, pi.Port, form.Action)

	errRespSize := 696969696969696969

	formatS := "-se -noninteractive -r -t 60 -r -o %s "
	formatS += "-u %s "
	formatS += "-w data/ffuf_testlist:USER -w data/ffuf_testlist:PASS "
	formatS += "-X POST -d %s=USER&%s=PASS -fs %d"
	argsS := fmt.Sprintf(formatS, c.jsonOut, targetUrl,
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
			Print(msg, c.name, err)
		}

		errRespSize, err = ffuf.GetRespSize(c.jsonOut)
		if err != nil {
			Print("ffuf weblogin: can't get resp size, skipping\n")
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

	c = t.prepareCmd(cname, "ffuf", pi.PortS, args)
	t.runCmd(c)

	err := ffuf.CleanFfuf(c.fileOut)
	if err != nil {
		msg := "error in %s: can't get clean ffuf output - %v\n"
		Print(msg, c.name, err)
	}

	ffufRes, ffufConfig, err := ffuf.GetResults(c.jsonOut)
	errExit(err)

	userCredsMap := make(map[string]CredsT)
	for _, res := range ffufRes {
		var creds CredsT
		creds.loc = res.Loc
		creds.user = res.Input.USER
		creds.pass = res.Input.PASS

		var data string
		data = str.Replace(ffufConfig.PostData, "USER", creds.user, -1)
		data = str.Replace(data, "PASS", creds.pass, -1)
		creds.postData = data

		userCredsMap[creds.user] = creds
	}

	for _, creds := range userCredsMap {
		creds.cookie, creds.redirLoc = getCookie(targetUrl, creds)
		t.Auth["weblogin"] = append(t.Auth["weblogin"], creds)
		if len(creds.cookie) != 0 {
			Print("[!]\tgot cookie for user %s: %s\n",
				creds.user, creds.cookie)
		}
	}
}

func getCookie(targetUrl string, creds CredsT) (string, string) {
	var redirLoc, cookie string

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("POST", targetUrl,
		str.NewReader(creds.postData))
	if err != nil {
		return cookie, redirLoc
	}
	req.Header.Set("Content-Type",
		"application/x-www-form-urlencoded; param=value")
	resp, err := client.Do(req)
	if err != nil {
		return cookie, redirLoc
	}
	if resp.StatusCode == 302 {
		redirLoc = resp.Header["Location"][0]
	}

	for _, c := range resp.Cookies() {
		switch c.Name {
		case "PHPSESSID":
			cookie = c.String()
		}
	}

	return cookie, redirLoc
}

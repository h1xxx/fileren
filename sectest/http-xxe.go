package sectest

import (
	"bufio"
	"fmt"
	"os"
	"time"

	str "strings"

	"sectest/xxe"
)

func (t *TargetT) testXxeInjection(host string, pi *PortInfoT, creds *CredsT) {
	cname := fmt.Sprintf("xxetest_%s_%d", host, pi.Port)
	if creds != nil {
		cname += "_" + creds.user
	}

	c := t.prepareCmd(cname, "xxe_lib", pi.PortS, []string{})
	if cmdIsDone(c.fileOut) {
		t.markCmdDone(c)
		return
	}

	Print("%s\t%s starting...\n", pi.PortS, cname)

	loc, xmlData, err := parseXxeReq(t.XxeReqFile)
	if err != nil {
		Print("error in xxetest: %v\n", err)
		return
	}

	var sslSuffix string
	if pi.Tunnel == "ssl" {
		sslSuffix = "s"
	}

	url := fmt.Sprintf("http%s://%s:%d%s", sslSuffix, host, pi.Port, loc)

	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	fd, err := os.OpenFile(c.fileOut, flags, 0640)
	errExit(err)
	printFileOutHeader(c, fd)
	fd.Close()

	// todo: add handling of linux hosts
	truncLog := false
	p, err := xxe.GetParams(url, xmlData, creds.cookie, c.outDir, c.fileOut,
		"data/files_win", t.Users, truncLog)

	if err != nil {
		Print("error in xxetest: %v\n", err)
		return
	}

	err = p.DirectTest()
	if err != nil {
		Print("error in xxetest: %v\n", err)
		c.status = "error"
	}

	if c.status == "" {
		c.status = "ok"
	}
	c.done = true
	c.runTime = time.Since(c.start)

	MU.Lock()
	t.Cmds[c.name] = c
	MU.Unlock()

	flags = os.O_CREATE | os.O_APPEND | os.O_WRONLY
	fd, err = os.OpenFile(c.fileOut, flags, 0640)
	errExit(err)
	defer fd.Close()

	printFileOutFooter(c, fd)
	msg := "%s\t%s done in %s, %s\n"
	Print(msg, c.portS, c.name, c.runTime.Round(time.Second), c.status)
}

func parseXxeReq(file string) (string, string, error) {
	fd, err := os.Open(file)
	if err != nil {
		return "", "", err
	}
	defer fd.Close()

	var loc, xmlData string
	var bodyStart bool

	i := 1
	input := bufio.NewScanner(fd)
	for input.Scan() {
		line := input.Text()

		if i == 1 && str.HasPrefix(line, "POST") {
			fields := str.Split(line, " ")
			if len(fields) < 2 {
				msg := "bad first line in request (no fields)"
				return "", "", fmt.Errorf(msg)
			}
			loc = fields[1]

		} else if i == 1 {
			msg := "bad first line in request (no POST)"
			return "", "", fmt.Errorf(msg)
		}

		if bodyStart && str.HasPrefix(line, "HTTP/1") {
			break
		}

		if line == "" {
			bodyStart = true
		}

		if bodyStart {
			xmlData += line
		}

		i++
	}

	return loc, xmlData, nil
}

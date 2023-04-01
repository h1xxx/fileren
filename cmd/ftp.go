package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"sync"

	str "strings"
)

func (t *targetT) testFtp(pi portInfoT) {
	print("testing %s on tcp port %d...\n", pi.service, pi.port)

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go t.ftpMirror("anonymous", "anonymous", pi, wg)
	go t.ftpBrute("1", pi, wg)
	wg.Wait()

	wg.Add(1)
	go t.ftpBrute("2", pi, wg)
	wg.Wait()

	wg.Add(1)
	go t.ftpBrute("3", pi, wg)
	wg.Wait()

	print("finished testing %s on tcp port %d\n", pi.service, pi.port)
	t.wg.Done()
}

func (t *targetT) ftpBrute(scan string, pi portInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("brute_%s_%d", scan, pi.port)

	var argsS string
	if scan == "1" {
		argsS = "-e nsr "
	}
	argsS += fmt.Sprintf("-L %s -P %s -I -u -t 64 -s %d ftp://%s",
		"./data/ftp_user", "./data/ftp_pass_"+scan, pi.port, t.host)

	args := str.Split(argsS, " ")

	c := t.prepareCmd(cname, "hydra", pi.portS, args)
	t.runCmd(c)
	wg.Done()
}

func (t *targetT) ftpMirror(user, pass string, pi portInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("lftp_%s_%d", user, pi.port)

	size, err := getFtpSize(t.host, user, pass, pi.port)
	var msg string
	if err != nil {
		msg = "%s\tftp user %s - can't get dir size, ignoring\n"
	} else if size > 1024 {
		msg = "%s\tftp user %s - dir size too big, ignoring\n"
	}
	if err != nil || size > 1024 {
		print(msg, pi.portS, user)
		wg.Done()
		return
	}

	formatS := "set net:max-retries 2; mirror -v "
	formatS += "-O %s/%s/mirror_%s; exit"
	ftpC := fmt.Sprintf(formatS, t.host, pi.portS, user)

	args := []string{"-e", ftpC}

	args = append(args, "-u")
	args = append(args, user+","+pass)

	args = append(args, "-p")
	args = append(args, fmt.Sprintf("%d", pi.port))
	args = append(args, t.host)

	c := t.prepareCmd(cname, "lftp", pi.portS, args)
	t.runCmd(c)

	wg.Done()
}

func getFtpSize(host, user, pass string, port int) (int, error) {
	c := []string{"-e", "set net:max-retries 2; du -m; exit"}

	c = append(c, "-u")
	c = append(c, user+","+pass)

	c = append(c, "-p")
	c = append(c, fmt.Sprintf("%d", port))
	c = append(c, host)

	cmd := exec.Command("lftp", c...)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	resS, _, found := str.Cut(string(out), "\t")
	res, err := strconv.Atoi(resS)
	if err != nil || !found {
		return 0, err
	}

	return res, nil
}

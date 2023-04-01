package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"time"

	fp "path/filepath"
	"sectest/nmap"
	str "strings"
)

func runCmd(host, portS string, c *cmdT) {
	outFile := fp.Join(host, portS, c.name+".out")
	if cmdIsDone(outFile) {
		print("%s\t%s already done, skipping\n", portS, c.name)
		c.status = "done"
		return
	}
	os.MkdirAll(fp.Join(host, portS), 0750)

	print("%s\t%s starting...\n", portS, c.name)

	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	fd, err := os.OpenFile(outFile, flags, 0640)
	errExit(err)
	defer fd.Close()

	fmt.Fprintf(fd, "sectest cmd: %s %s\n", c.bin, str.Join(c.args, " "))
	fmt.Fprintf(fd, "%s\n", str.Repeat("-", 79))

	cmd := exec.Command(c.bin, c.args...)
	cmd.Stdout = fd
	cmd.Stderr = fd

	c.start = time.Now()
	err = cmd.Run()

	if errInOutFile(outFile) {
		c.status = "error"
	} else if err == nil || c.exitCodeIgnore {
		c.status = "ok"
	} else {
		c.status = "error"
	}

	c.runTime = time.Since(c.start)

	fmt.Fprintf(fd, "%s\n", str.Repeat("-", 79))
	fmt.Fprintf(fd, "sectest cmd status: %s\n", c.status)
	fmt.Fprintf(fd, "sectest cmd time: %s\n", c.runTime.Round(time.Second))

	msg := "%s\t%s done in %s, %s\n"
	print(msg, portS, c.name, c.runTime.Round(time.Second), c.status)
}

func cmdIsDone(outFile string) bool {
	cmd := exec.Command("grep", "-q", "sectest cmd status: ok", outFile)
	err := cmd.Run()
	if err != nil {
		return false
	}
	return true
}

func errInOutFile(outFile string) bool {
	errStrings := []string{
		"Receiving spurious errors, exiting.",
	}

	var q []string
	q = append(q, "-F")
	q = append(q, "-q")
	for _, s := range errStrings {
		q = append(q, "-e")
		q = append(q, s)
	}
	q = append(q, outFile)

	cmd := exec.Command("grep", q...)
	err := cmd.Run()
	if err != nil {
		return false
	}
	return true
}

func (t *targetT) printInfo() {
	fmt.Printf("\nhost:\t\t%s\n", t.host)

	for p, k := range t.tcp {
		fmt.Printf("tcp %d:\t\t%+v\n", p, k)
	}

	for p, k := range t.udp {
		fmt.Printf("udp %d:\t\t%+v\n", p, k)
	}

	return

	for name, c := range t.cmds {
		fmt.Printf("\ncmd:\t\t%s\n", name)
		if c.status != "done" {
			fmt.Printf("status:\t\t%s\n", c.status)
			fmt.Printf("start time:\t%s\n",
				c.start.Format("2006-01-02 15:04:05"))
			fmt.Printf("runtime:\t%s\n",
				c.runTime.Round(time.Second))
		}
		if str.Contains(c.name, "_fast") {
			nmap.PrHostInfo(c.nmapScan)
		}
	}
}

func getRandomUA() string {
	fd, err := os.Open("./data/http_user-agent")
	errExit(err)
	defer fd.Close()

	var lines []string
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}

	rand.Seed(time.Now().UnixNano())
	i := rand.Intn(len(lines))

	return lines[i]
}

func print(format string, a ...any) {
	MU.Lock()
	fmt.Printf(format, a...)
	MU.Unlock()
}

func errExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

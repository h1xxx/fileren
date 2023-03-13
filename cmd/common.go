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

func runCmd(host string, c *cmdT) {
	outFile := fp.Join(host, c.name)
	if cmdIsDone(outFile) {
		print("%s already done; skipping.\n", c.name)
		c.status = "done"
		return
	}

	print("starting %s...\n", c.name)

	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	fd, err := os.OpenFile(outFile, flags, 0640)
	errExit(err)

	fmt.Fprintf(fd, "sectest cmd: %s %s\n", c.bin, str.Join(c.args, " "))
	sep := "---------------------------------------"
	fmt.Fprintf(fd, "%s%s-\n", sep, sep)

	cmd := exec.Command(c.bin, c.args...)
	cmd.Stdout = fd
	cmd.Stderr = fd

	c.start = time.Now()
	err = cmd.Run()

	if err == nil {
		c.status = "ok"
	} else {
		c.status = "error"
	}

	c.runTime = time.Since(c.start)

	fmt.Fprintf(fd, "%s%s-\n", sep, sep)
	fmt.Fprintf(fd, "sectest cmd status: %s\n", c.status)
	fmt.Fprintf(fd, "sectest cmd time: %s\n", c.runTime.Round(time.Second))

	msg := "%s done in %s; status: %s.\n"
	print(msg, c.name, c.runTime.Round(time.Second), c.status)

	fd.Close()
}

func cmdIsDone(outFile string) bool {
	cmd := exec.Command("grep", "-q", "sectest cmd status: ok", outFile)
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
	uaPath := "/usr/share/seclists/Fuzzing/User-Agents"
	fd, err := os.Open(uaPath + "/operating-system-name/windows.txt")
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

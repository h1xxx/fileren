package sectest

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"sync"
	"time"

	fp "path/filepath"
	"sectest/nmap"
	str "strings"
)

var MU = &sync.Mutex{}

func (t *TargetT) prepareCmd(cname, bin, portS string, args []string) CmdT {
	var c CmdT
	c.name = cname
	c.bin = bin
	c.args = args
	c.portS = portS

	c.fileOut = fp.Join(t.Host, portS, c.name+".out")
	c.jsonOut = fp.Join(t.Host, portS, c.name+".json")

	MU.Lock()
	// first check if cmd already exists and has non-empty args
	// non-empty args are allowed to set initial file paths
	val, keyExists := t.Cmds[c.name]
	if keyExists && len(val.args) != 0 {
		errExit(fmt.Errorf("non-unique cmd name: %s", cname))
	}

	// add command to the global state
	t.Cmds[c.name] = c
	MU.Unlock()

	os.MkdirAll(fp.Join(t.Host, portS), 0750)

	return c
}

func (t *TargetT) runCmd(c CmdT) {
	if cmdIsDone(c.fileOut) {
		Print("%s\t%s already done\n", c.portS, c.name)
		c.status = "ok"
		c.done = true

		MU.Lock()
		t.Cmds[c.name] = c
		MU.Unlock()

		return
	}

	Print("%s\t%s starting...\n", c.portS, c.name)

	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	fd, err := os.OpenFile(c.fileOut, flags, 0640)
	errExit(err)
	defer fd.Close()

	fmt.Fprintf(fd, "sectest cmd: %s %s\n", c.bin, getQuotedArgs(c.args))
	fmt.Fprintf(fd, "%s\n", str.Repeat("-", 79))

	cmd := exec.Command(c.bin, c.args...)
	cmd.Stdout = fd
	cmd.Stderr = fd

	c.start = time.Now()
	err = cmd.Run()

	if errInOutFile(c.fileOut) {
		c.status = "error"
	} else if err == nil || c.exitCodeIgnore {
		c.status = "ok"
	} else {
		c.status = "error"
	}

	c.done = true
	c.runTime = time.Since(c.start)

	MU.Lock()
	t.Cmds[c.name] = c
	MU.Unlock()

	fmt.Fprintf(fd, "%s\n", str.Repeat("-", 79))
	fmt.Fprintf(fd, "sectest cmd status: %s\n", c.status)
	fmt.Fprintf(fd, "sectest cmd time: %s\n", c.runTime.Round(time.Second))

	msg := "%s\t%s done in %s, %s\n"
	Print(msg, c.portS, c.name, c.runTime.Round(time.Second), c.status)
}

func (t *TargetT) AllScheduled() bool {
	if t.portsStarted() && t.TcpScanned && t.UdpScanned {
		return true
	}
	return false
}

func (t *TargetT) portsStarted() bool {
	for _, pi := range t.Tcp {
		if !pi.Started {
			return false
		}
	}
	for _, pi := range t.Udp {
		if !pi.Started {
			return false
		}
	}
	return true
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
		"Unable to establish SSL connection",
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

func (t *TargetT) printInfo() {
	fmt.Printf("\nhost:\t\t%s\n", t.Host)

	for p, k := range t.Tcp {
		fmt.Printf("tcp %d:\t\t%+v\n", p, k)
	}

	for p, k := range t.Udp {
		fmt.Printf("udp %d:\t\t%+v\n", p, k)
	}

	return

	for name, c := range t.Cmds {
		fmt.Printf("\ncmd:\t\t%s\n", name)
		if c.status != "done" {
			fmt.Printf("status:\t\t%s\n", c.status)
			fmt.Printf("start time:\t%s\n",
				c.start.Format("2006-01-02 15:04:05"))
			fmt.Printf("runtime:\t%s\n",
				c.runTime.Round(time.Second))
		}
		if str.Contains(c.name, "_init") {
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

func getQuotedArgs(args []string) string {
	var quotedArgs, sep string

	for _, a := range args {
		quoteChar := "'"
		if str.Contains(a, "'") {
			quoteChar = "\""
		}

		if stringNeedsQuote(a) {
			quotedArgs += sep + quoteChar + a + quoteChar
		} else {
			quotedArgs += sep + a
		}
		sep = " "
	}

	return quotedArgs
}

func stringNeedsQuote(s string) bool {
	toQuoteChars := []string{
		" ", ";", "'", "\"", "`",
		"(", ")", "[", "]", "{", "}",
		"\\", "<", ">", "&"}

	for _, c := range toQuoteChars {
		if str.Contains(s, c) {
			return true
		}
	}

	return false
}

func Print(format string, a ...any) {
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

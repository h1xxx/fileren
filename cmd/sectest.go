package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"sync"
	"time"

	fp "path/filepath"
	str "strings"
)

type targetT struct {
	ip   string
	tcp  map[string]portT
	udp  map[string]portT
	cmds map[string]cmdT

	wg *sync.WaitGroup
}

// status: "ok" or "error"
type cmdT struct {
	name    string
	bin     string
	args    []string
	out     string
	status  string
	start   time.Time
	runTime time.Duration
}

type portT struct {
	done   bool
	isSsh  bool
	isHttp bool
	isApi  bool
}

var MU = &sync.Mutex{}

func main() {
	var t targetT
	t.ip = "scanme.nmap.org"
	t.tcp = make(map[string]portT)
	t.udp = make(map[string]portT)
	t.cmds = make(map[string]cmdT)

	os.MkdirAll(fp.Join(t.ip, "nmap"), 0750)
	t.wg = &sync.WaitGroup{}

	fmt.Println("starting all nmap scans...")
	t.wg.Add(5)

	c := t.makeNmapCmd("nmap_tcp_fast_1", "-p1-10000 -sSVC")
	go t.nmapRun(c)

	c = t.makeNmapCmd("nmap_tcp_fast_2", "-p10001-65535 -sSVC")
	go t.nmapRun(c)

	c = t.makeNmapCmd("nmap_tcp_full", "-p- -sS -sV -O")
	go t.nmapRun(c)

	c = t.makeNmapCmd("nmap_udp_fast", "--top-ports 50 -sUVC")
	go t.nmapRun(c)

	c = t.makeNmapCmd("nmap_udp_full", "--top-ports 1000 -sUV")
	go t.nmapRun(c)

	t.wg.Wait()
	t.printInfo()
}

func (t targetT) makeNmapCmd(name, argsS string) cmdT {
	var c cmdT
	c.name = name
	c.bin = "nmap"

	if str.Contains(name, "_fast") {
		argsS += " --script-timeout 3 --max-retries 2"
	}

	argsS += " -T4 -g53 -oX " + fp.Join(t.ip, "nmap", name+".xml ")
	argsS += "-oG " + fp.Join(t.ip, "nmap", name+".grep ")
	argsS += t.ip

	c.args = str.Split(argsS, " ")

	scripts := "(auth or default or discovery or intrusive or vuln) and "
	scripts += "not (*robtex* or *brute* or ssh-run or http-slowloris)"

	if str.Contains(name, "_full") {
		c.args = append(c.args, "--version-all")
		c.args = append(c.args, "--script")
		c.args = append(c.args, scripts)
	}

	c.args = append(c.args, "--script-args")
	c.args = append(c.args, "http.useragent="+getRandomUA())

	return c
}

func (t targetT) nmapRun(c cmdT) {
	runCmd(&c)

	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	fd, err := os.OpenFile(fp.Join(t.ip, c.name), flags, 0640)
	errExit(err)
	fmt.Fprintf(fd, c.out)
	fd.Close()

	MU.Lock()
	t.cmds[c.name] = c
	fmt.Printf("%s done in %s; status: %s\n",
		c.name, c.runTime.Round(time.Second), c.status)
	MU.Unlock()

	t.wg.Done()
}

func runCmd(c *cmdT) {
	cmd := exec.Command(c.bin, c.args...)

	c.start = time.Now()
	out, err := cmd.CombinedOutput()
	if err == nil {
		c.status = "ok"
	} else {
		c.status = "error"
	}

	c.out = string(out)

	c.runTime = time.Since(c.start)
}

func (t targetT) printInfo() {
	fmt.Printf("\nip:\t\t%s\n", t.ip)

	for p, k := range t.tcp {
		fmt.Printf("tcp %s:\t\t%+v\n", p, k)
	}

	for p, k := range t.udp {
		fmt.Printf("udp %s:\t\t%+v\n", p, k)
	}

	for name, c := range t.cmds {
		fmt.Printf("\ncmd:\t\t%s\n", name)
		fmt.Printf("status:\t\t%s\n", c.status)
		fmt.Printf("start time:\t%s\n",
			c.start.Format("2006-01-02 15:04:05"))
		fmt.Printf("runtime:\t%s\n", c.runTime.Round(time.Second))
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

func errExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

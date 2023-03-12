package main

import (
	"bufio"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"sync"
	"time"

	fp "path/filepath"
	str "strings"

	"sectest/nmap"
)

type targetT struct {
	ip   string
	tcp  map[int]portT
	udp  map[int]portT
	cmds map[string]cmdT

	tcpScanned  bool
	tcp1Scanned bool
	tcp2Scanned bool
	udpScanned  bool
	wg          *sync.WaitGroup
}

// status: "ok", "error" or "done"
type cmdT struct {
	name     string
	bin      string
	args     []string
	out      string
	status   string
	start    time.Time
	runTime  time.Duration
	nmapScan nmap.HostT
}

type portT struct {
	started bool
	service string
	product string
	ver     string
}

var MU = &sync.Mutex{}

func main() {
	var t targetT
	t.ip = "scanme.nmap.org"
	t.tcp = make(map[int]portT)
	t.udp = make(map[int]portT)
	t.cmds = make(map[string]cmdT)

	t.wg = &sync.WaitGroup{}

	os.MkdirAll(fp.Join(t.ip, "nmap"), 0750)

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

	for {
		time.Sleep(3 * time.Second)
		for p, info := range t.tcp {
			if !info.started {
				// cmon do someting
				info.started = true
				t.tcp[p] = info
			}
		}

		for p, info := range t.udp {
			if !info.started {
				// cmon do someting
				info.started = true
				t.udp[p] = info
			}
		}

		if t.portsStarted() && t.tcpScanned && t.udpScanned {
			break
		}
	}

	t.wg.Wait()
	t.printInfo()
}

func (t *targetT) portsStarted() bool {
	for _, info := range t.tcp {
		if !info.started {
			return false
		}
	}
	for _, info := range t.udp {
		if !info.started {
			return false
		}
	}
	return true
}

func (t *targetT) makeNmapCmd(name, argsS string) cmdT {
	var c cmdT
	c.name = name
	c.bin = "nmap"

	if str.Contains(name, "_fast") {
		argsS += " --script-timeout 3 --max-retries 2"
	}

	argsS += " -T4 -g53 -oX " + fp.Join(t.ip, "nmap", name+".xml")
	argsS += " -oG " + fp.Join(t.ip, "nmap", name+".grep")
	argsS += " " + t.ip

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

func (t *targetT) nmapRun(c cmdT) {
	outFile := fp.Join(t.ip, c.name)

	// execute nmap only if scan is not already completed
	_, err := os.Stat(outFile)
	if errors.Is(err, os.ErrNotExist) {
		runCmd(&c)

		flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
		fd, err := os.OpenFile(outFile, flags, 0640)
		errExit(err)
		fmt.Fprintf(fd, c.out)
		fd.Close()
	}

	nmapScan, err := nmap.ReadScan(fp.Join(t.ip, "nmap", c.name+".xml"))
	c.nmapScan = nmapScan.Hosts[0]
	errExit(err)

	MU.Lock()
	if c.status == "" {
		fmt.Printf("%s already done; skipping.\n", c.name)
		c.status = "done"
	} else {
		fmt.Printf("%s done in %s; status: %s\n",
			c.name, c.runTime.Round(time.Second), c.status)
	}
	t.cmds[c.name] = c
	t.getTestPorts(c)
	MU.Unlock()

	switch c.name {
	case "nmap_tcp_fast_1":
		t.tcp1Scanned = true
	case "nmap_tcp_fast_2":
		t.tcp2Scanned = true
	case "nmap_udp_fast":
		t.udpScanned = true
	}

	if t.tcp1Scanned && t.tcp2Scanned {
		t.tcpScanned = true
	}

	t.wg.Done()
}

func (t *targetT) getTestPorts(c cmdT) {
	switch c.name {
	case "nmap_tcp_fast_1", "nmap_tcp_fast_2":
		for _, p := range c.nmapScan.Ports {
			if p.State.State != "open" {
				continue
			}

			var info portT

			info.service = p.Service.Name
			info.product = p.Service.Product
			info.ver = p.Service.Ver

			t.tcp[p.PortId] = info
		}

	case "nmap_udp_fast":
		for _, p := range c.nmapScan.Ports {
			if p.State.State != "open" {
				continue
			}

			var info portT

			info.service = p.Service.Name
			info.product = p.Service.Product
			info.ver = p.Service.Ver

			t.udp[p.PortId] = info
		}
	}
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

func (t *targetT) printInfo() {
	fmt.Printf("\nip:\t\t%s\n", t.ip)

	for p, k := range t.tcp {
		fmt.Printf("tcp %d:\t\t%+v\n", p, k)
	}

	for p, k := range t.udp {
		fmt.Printf("udp %d:\t\t%+v\n", p, k)
	}

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

func errExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

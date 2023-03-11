package main

import (
	"fmt"
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

type cmdT struct {
	name    string
	bin     string
	args    []string
	out     string
	ok      bool
	done    bool
	start   time.Time
	seconds int
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
	t.ip = "10.129.95.191"
	t.tcp = make(map[string]portT)
	t.udp = make(map[string]portT)
	t.cmds = make(map[string]cmdT)

	os.MkdirAll(t.ip, 0750)
	t.wg = &sync.WaitGroup{}

	fmt.Println("starting nmap_tcp_fast...")
	t.wg.Add(4)

	c := t.makeNmapCmd("nmap_tcp_fast", "--top-ports 1000")
	go t.nmapRun(c)

	fmt.Println("starting nmap_tcp_full...")
	c = t.makeNmapCmd("nmap_tcp_full", "-p -")
	go t.nmapRun(c)

	fmt.Println("starting nmap_udp_full...")
	c = t.makeNmapCmd("nmap_udp_fast", "--top-ports 50 -sU")
	go t.nmapRun(c)

	fmt.Println("starting nmap_udp_full...")
	c = t.makeNmapCmd("nmap_udp_full", "--top-ports 1000 -sU")
	go t.nmapRun(c)

	t.wg.Wait()

	t.printInfo()
}

func (t targetT) makeNmapCmd(name, argsS string) cmdT {
	var c cmdT
	c.name = name
	c.bin = "nmap"

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, []string{"-T", "4", "-sV", "-sC"}...)
	c.args = append(c.args, []string{"-oX", fp.Join(t.ip, name+".xml")}...)
	c.args = append(c.args, []string{t.ip}...)

	return c
}

func (t targetT) nmapRun(c cmdT) {
	runCmd(&c)

	MU.Lock()
	t.cmds[c.name] = c
	MU.Unlock()

	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	fd, err := os.OpenFile(fp.Join(t.ip, c.name), flags, 0640)
	errExit(err)
	fmt.Fprintf(fd, c.out)
	fd.Close()

	t.wg.Done()
}

func runCmd(c *cmdT) {
	cmd := exec.Command(c.bin, c.args...)

	c.start = time.Now()
	out, err := cmd.CombinedOutput()
	if err == nil {
		c.ok = true
	}

	c.out = string(out)
	c.done = true

	runTime := time.Since(c.start)
	c.seconds = int(runTime.Seconds())
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
		fmt.Printf("ok:\t\t%v\n", c.ok)
		fmt.Printf("start time:\t%s\n",
			c.start.Format("2006-01-02 15:04:05"))
		fmt.Printf("runtime:\t%ds\n", c.seconds)
	}
}

func errExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

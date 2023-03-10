package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

type cmdT struct {
	bin     string
	args    []string
	out     string
	ok      bool
	done    bool
	start   time.Time
	seconds int
}

// types:
// - ssh
// - www
// - api
type portT struct {
	portType map[string]bool
	done     bool
}

type targetT struct {
	ip   string
	tcp  map[string]portT
	udp  map[string]portT
	cmds map[string]cmdT
}

func main() {
	var t targetT
	t.ip = "10.129.140.98"
	t.tcp = make(map[string]portT)
	t.udp = make(map[string]portT)
	t.cmds = make(map[string]cmdT)

	fmt.Println("starting nmap_tcp_fast...")
	t.nmapTcpFast()

	t.printInfo()
}

func (t targetT) nmapTcpFast() {
	name := "nmap_tcp_fast"

	var c cmdT
	c.bin = "nmap"
	c.args = []string{"-p", "22", "-sV", "-sC", t.ip}

	runCmd(&c)
	t.cmds[name] = c
}

func runCmd(c *cmdT) {
	cmd := exec.Command(c.bin, c.args...)

	c.start = time.Now()
	out, err := cmd.CombinedOutput()
	errExit(err)

	c.out = string(out)

	t := time.Since(c.start)
	c.seconds = int(t.Seconds())
}

func (t targetT) printInfo() {
	fmt.Printf("\nip:\t\t%s\n", t.ip)

	for p, k := range t.tcp {
		fmt.Printf("tcp %s:\t\t%s\n", p, k.portType)
	}

	for p, k := range t.udp {
		fmt.Printf("udp %s:\t\t%s\n", p, k.portType)
	}

	for name, c := range t.cmds {
		fmt.Printf("\ncommand:\t%s\n", name)
		fmt.Printf("runtime:\t%ds\n", c.seconds)
		fmt.Println(c.out)
	}
}

func errExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

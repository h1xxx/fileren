package main

// deps:
// nmap
// vulners

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	fp "path/filepath"

	"sectest/html"
	"sectest/nmap"
)

type targetT struct {
	host string
	tcp  map[int]portInfoT
	udp  map[int]portInfoT
	cmds map[string]cmdT

	tcpScanned  bool
	tcp1Scanned bool
	tcp2Scanned bool
	udpScanned  bool

	tcpFullStarted bool
	udpFullStarted bool
	httpInProgress bool
	wg             *sync.WaitGroup
}

// status: "ok", "error" or "done"
type cmdT struct {
	name           string
	bin            string
	args           []string
	exitCodeIgnore bool
	status         string
	start          time.Time
	runTime        time.Duration
	nmapScan       nmap.HostT
}

type portInfoT struct {
	started bool

	port  int
	portS string

	service string
	tunnel  string
	product string
	ver     string

	loginParams []html.LoginParamsT
}

type argsT struct {
	host    *string
	domains *string
}

var MU = &sync.Mutex{}
var args argsT

func init() {
	args.host = flag.String("t", "", "target host (ip or domain)")
	args.domains = flag.String("d", "", "domains for web enumaration")
}

func main() {
	flag.Parse()
	if *args.host == "" {
		errExit(fmt.Errorf("target host parameter missing (-h)"))
	}

	var t targetT
	t.host = *args.host
	t.tcp = make(map[int]portInfoT)
	t.udp = make(map[int]portInfoT)
	t.cmds = make(map[string]cmdT)

	t.wg = &sync.WaitGroup{}

	os.MkdirAll(fp.Join(t.host, "nmap"), 0750)

	t.wg.Add(5)

	c := t.makeNmapCmd("tcp_fast_1", "-p1-10000 -sSV")
	go t.nmapRun(c)
	time.Sleep(10 * time.Millisecond)

	c = t.makeNmapCmd("tcp_fast_2", "-p10001-65535 -sSV")
	go t.nmapRun(c)
	time.Sleep(10 * time.Millisecond)

	c = t.makeNmapCmd("udp_fast", "--top-ports 50 -sUV")
	go t.nmapRun(c)

	// polling loop to start testing new ports that appear from nmap scans
	for {
		// start tcp full scan only when fast scans are completed
		if t.tcpScanned && !t.tcpFullStarted {
			t.tcpFullStarted = true
			c = t.makeNmapCmd("tcp_full", "-p- -sS -sV -O")
			go t.nmapRun(c)
		}

		// start udp full scan only when fast scan is completed
		if t.udpScanned && !t.udpFullStarted {
			t.udpFullStarted = true
			c = t.makeNmapCmd("udp_full", "--top-ports 500 -sUV")
			go t.nmapRun(c)
		}

		// search for new tcp ports that appear from nmap fast scans
		for p, pi := range t.tcp {
			if pi.started {
				continue
			}

			switch pi.service {
			case "ftp":
				t.wg.Add(1)
				pi.started = true
				go t.testFtp(pi)
				t.tcp[p] = pi
			case "ssh":
				t.wg.Add(1)
				pi.started = true
				go t.testSsh(pi)
				t.tcp[p] = pi
			case "http":
				if !t.httpInProgress {
					t.httpInProgress = true
					pi.started = true
					t.wg.Add(1)
					go t.testHttp(&pi)
					t.tcp[p] = pi
				}
			case "http-proxy":
				if !t.httpInProgress {
					t.httpInProgress = true
					t.wg.Add(1)
					pi.started = true
					go t.testHttp(&pi)
					t.tcp[p] = pi
				}
			default:
				msg := "ignoring %s on tcp port %d\n"
				print(msg, pi.service, p)
			}
		}

		// search for new udp ports that appear from nmap fast scans
		for p, pi := range t.udp {
			if pi.started {
				continue
			}

			switch pi.service {
			default:
				msg := "ignoring %s on udp port %d\n"
				print(msg, pi.service, p)
			}

			pi.started = true
			t.udp[p] = pi
		}

		// slow down the loop and exit if all ports are being tested
		time.Sleep(3 * time.Second)
		if t.allScheduled() {
			break
		}
	}

	t.wg.Wait()
	//t.printInfo()
}

func (t *targetT) allScheduled() bool {
	if t.portsStarted() && t.tcpScanned && t.udpScanned {
		if t.tcpFullStarted && t.udpFullStarted {
			return true
		}
	}
	return false
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

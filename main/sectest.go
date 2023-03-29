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
	wg          *sync.WaitGroup
}

// status: "ok", "error" or "done"
type cmdT struct {
	name      string
	bin       string
	args      []string
	errIgnore bool
	status    string
	start     time.Time
	runTime   time.Duration
	nmapScan  nmap.HostT
}

type portInfoT struct {
	started bool
	port    int
	service string
	tunnel  string
	product string
	ver     string
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

	c := t.makeNmapCmd("tcp_fast_1", "-p1-10000 -sSVC")
	go t.nmapRun(c)

	c = t.makeNmapCmd("tcp_fast_2", "-p10001-65535 -sSVC")
	go t.nmapRun(c)

	c = t.makeNmapCmd("tcp_full", "-p- -sS -sV -O")
	go t.nmapRun(c)

	c = t.makeNmapCmd("udp_fast", "--top-ports 50 -sUVC")
	go t.nmapRun(c)

	c = t.makeNmapCmd("udp_full", "--top-ports 1000 -sUV")
	go t.nmapRun(c)

	// wait a bit before other cmds are executed to print nmap info at once
	time.Sleep(100 * time.Millisecond)

	return

	for {
		for p, pi := range t.tcp {
			if pi.started {
				continue
			}

			switch pi.service {
			case "ftp":
				t.wg.Add(1)
				go t.testFtp(pi)
			case "ssh":
				t.wg.Add(1)
				go t.testSsh(pi)
			case "http":
				t.wg.Add(1)
				go t.testHttp(pi)
			case "http-proxy":
				t.wg.Add(1)
				go t.testHttp(pi)
			default:
				msg := "ignoring %s on tcp port %d.\n"
				print(msg, pi.service, p)
			}

			pi.started = true
			t.tcp[p] = pi
		}

		for p, pi := range t.udp {
			if pi.started {
				continue
			}

			switch pi.service {
			default:
				msg := "ignoring %s on udp port %d.\n"
				print(msg, pi.service, p)
			}

			pi.started = true
			t.udp[p] = pi
		}

		time.Sleep(3 * time.Second)
		if t.portsStarted() && t.tcpScanned && t.udpScanned {
			break
		}
	}

	t.wg.Wait()
	//t.printInfo()
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

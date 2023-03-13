package main

// deps:
// nmap
// vulners

import (
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
	name     string
	bin      string
	args     []string
	status   string
	start    time.Time
	runTime  time.Duration
	nmapScan nmap.HostT
}

type portInfoT struct {
	started bool
	service string
	product string
	ver     string
}

var MU = &sync.Mutex{}

func main() {
	var t targetT
	t.host = "scanme.nmap.org"
	t.tcp = make(map[int]portInfoT)
	t.udp = make(map[int]portInfoT)
	t.cmds = make(map[string]cmdT)

	t.wg = &sync.WaitGroup{}

	os.MkdirAll(fp.Join(t.host, "nmap"), 0750)

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
		for p, pi := range t.tcp {
			if pi.started {
				continue
			}

			switch pi.service {
			case "ssh":
				t.testSsh(p, pi)
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

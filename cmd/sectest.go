package main

// deps:
// nmap
// vulners

import (
	"flag"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	fp "path/filepath"

	"sectest/html"
	"sectest/nmap"
)

type credsT struct {
	loc      string
	redirLoc string

	user     string
	pass     string
	postData string
	cookie   string
}

// cmds maps command names to cmdT structs
// auth possible keys: "ssh, "ftp", "weblogin"
type targetT struct {
	host string
	tcp  map[int]portInfoT
	udp  map[int]portInfoT
	cmds map[string]cmdT
	info map[infoKeyT]string

	auth map[string][]credsT

	start   time.Time
	runTime time.Duration

	tcpScanned bool
	udpScanned bool

	httpInProgress bool
	wg             *sync.WaitGroup
}

// status: "ok" or "error"
type cmdT struct {
	name           string
	bin            string
	args           []string
	exitCodeIgnore bool

	portS   string
	fileOut string
	jsonOut string

	nmapScan nmap.HostT

	start   time.Time
	runTime time.Duration
	status  string
	started bool
	done    bool
	resDone bool
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

type infoKeyT struct {
	name  string
	portS string
}

type argsT struct {
	host      *string
	skipPorts *string
}

var MU = &sync.Mutex{}
var ARGS argsT

func init() {
	ARGS.host = flag.String("t", "", "target host (ip or domain)")

	msg := "ports to skip, e.g '80t' or '22t,443t,53u'"
	ARGS.skipPorts = flag.String("s", "", msg)
}

func main() {
	flag.Parse()
	if *ARGS.host == "" {
		errExit(fmt.Errorf("target host parameter missing (-h)"))
	}

	var t targetT
	t.host = *ARGS.host
	t.start = time.Now()
	t.tcp = make(map[int]portInfoT)
	t.udp = make(map[int]portInfoT)
	t.cmds = make(map[string]cmdT)
	t.info = make(map[infoKeyT]string)
	t.auth = make(map[string][]credsT)

	t.wg = &sync.WaitGroup{}

	os.MkdirAll(fp.Join(t.host, "nmap"), 0750)

	t.wg.Add(2)

	c := t.makeNmapCmd("tcp_init", "nmap", "-sSV -T4 -p-")
	t.nmapRun(c, t.wg)

	c = t.makeNmapCmd("udp_init", "nmap", "-sUV --top-ports 1000")
	go t.nmapRun(c, t.wg)

	// polling goroutine to grab results as soon as they're found
	wgPoll := &sync.WaitGroup{}
	wgPoll.Add(1)
	stopResPoll := make(chan bool)
	go t.pollResults(stopResPoll, wgPoll)

	// polling loop to start testing new ports that appear from nmap scans
	for {
		// search for new tcp ports that appear from nmap init scans
		for p, pi := range t.tcp {
			if pi.started {
				continue
			}

			switch pi.service {
			case "ftp":
				t.wg.Add(1)
				pi := pi
				pi.started = true
				t.tcp[p] = pi
				go t.testFtp(pi)
			case "ssh":
				t.wg.Add(1)
				pi := pi
				pi.started = true
				t.tcp[p] = pi
				go t.testSsh(pi)
			case "http":
				if !t.httpInProgress {
					t.httpInProgress = true
					t.wg.Add(1)
					pi := pi
					pi.started = true
					t.tcp[p] = pi
					go t.testHttp(&pi)
				}
			case "http-proxy":
				if !t.httpInProgress {
					t.httpInProgress = true
					t.wg.Add(1)
					pi := pi
					pi.started = true
					t.tcp[p] = pi
					go t.testHttp(&pi)
				}
			default:
				pi := pi
				pi.started = true
				t.tcp[p] = pi
				msg := "ignoring %s on tcp port %d\n"
				print(msg, pi.service, p)
			}
		}

		// search for new udp ports that appear from nmap init scans
		for p, pi := range t.udp {
			if pi.started {
				continue
			}

			switch pi.service {
			default:
				msg := "ignoring %s on udp port %d\n"
				print(msg, pi.service, p)

				pi := pi
				pi.started = true
				t.udp[p] = pi
			}
		}

		// slow down the loop and exit if all ports are being tested
		t.runTime = time.Since(t.start)
		delay := int(math.Min(t.runTime.Minutes()+1, 15))
		time.Sleep(time.Duration(delay) * time.Second)
		if t.allScheduled() {
			break
		}
	}

	t.wg.Wait()
	stopResPoll <- true
	wgPoll.Wait()

	t.runTime = time.Since(t.start)
	print("all done in %s\n", t.runTime.Round(time.Second))
}

func (t *targetT) allScheduled() bool {
	if t.portsStarted() && t.tcpScanned && t.udpScanned {
		return true
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

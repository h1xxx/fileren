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

	st "sectest/sectest"
)

type argsT struct {
	host      *string
	skipPorts *string
}

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

	t := targetInit()

	t.Wg.Add(2)

	c := t.MakeNmapCmd("tcp_init", "nmap", "-sSV -T4 -p-")
	t.NmapRun(c, t.Wg)

	c = t.MakeNmapCmd("udp_init", "nmap", "-sUV --top-ports 1000")
	go t.NmapRun(c, t.Wg)

	// polling goroutine to grab results as soon as they're found
	wgPoll := &sync.WaitGroup{}
	wgPoll.Add(1)
	stopResPoll := make(chan bool)
	go t.PollResults(stopResPoll, wgPoll)

	// polling loop to start testing new ports that appear from nmap scans
	for {
		// search for new tcp ports that appear from nmap init scans
		for p, pi := range t.Tcp {
			if pi.Started {
				continue
			}

			switch pi.Service {
			case "ftp":
				t.Wg.Add(1)
				pi := pi
				pi.Started = true
				t.Tcp[p] = pi
				go t.TestFtp(pi)
			case "ssh":
				t.Wg.Add(1)
				pi := pi
				pi.Started = true
				t.Tcp[p] = pi
				go t.TestSsh(pi)
			case "http":
				if !t.HttpInProgress {
					t.HttpInProgress = true
					t.Wg.Add(1)
					pi := pi
					pi.Started = true
					t.Tcp[p] = pi
					go t.TestHttp(&pi)
				}
			case "http-proxy":
				if !t.HttpInProgress {
					t.HttpInProgress = true
					t.Wg.Add(1)
					pi := pi
					pi.Started = true
					t.Tcp[p] = pi
					go t.TestHttp(&pi)
				}
			default:
				pi := pi
				pi.Started = true
				t.Tcp[p] = pi
				msg := "ignoring %s on tcp port %d\n"
				print(msg, pi.Service, p)
			}
		}

		// search for new udp ports that appear from nmap init scans
		for p, pi := range t.Udp {
			if pi.Started {
				continue
			}

			switch pi.Service {
			default:
				msg := "ignoring %s on udp port %d\n"
				print(msg, pi.Service, p)

				pi := pi
				pi.Started = true
				t.Udp[p] = pi
			}
		}

		// slow down the loop and exit if all ports are being tested
		t.RunTime = time.Since(t.Start)
		delay := int(math.Min(t.RunTime.Minutes()+1, 15))
		time.Sleep(time.Duration(delay) * time.Second)
		if t.AllScheduled() {
			break
		}
	}

	t.Wg.Wait()
	stopResPoll <- true
	wgPoll.Wait()

	t.RunTime = time.Since(t.Start)
	print("all done in %s\n", t.RunTime.Round(time.Second))
}

func targetInit() st.TargetT {
	var t st.TargetT
	t.Host = *ARGS.host
	t.SkipPorts = *ARGS.skipPorts
	t.Start = time.Now()
	t.Tcp = make(map[int]st.PortInfoT)
	t.Udp = make(map[int]st.PortInfoT)
	t.Cmds = make(map[string]st.CmdT)
	t.Info = make(map[st.InfoKeyT]string)
	t.Auth = make(map[string][]st.CredsT)
	t.Wg = &sync.WaitGroup{}

	os.MkdirAll(fp.Join(t.Host, "nmap"), 0750)

	return t
}

func errExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

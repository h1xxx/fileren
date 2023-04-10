package sectest

import (
	"fmt"
	"sync"

	fp "path/filepath"
	str "strings"

	"sectest/nmap"
)

func (t *TargetT) MakeNmapCmd(name, portS, argsS string) CmdT {
	cname := name

	argsS += " -g53 --open --max-retries 1 -v"
	argsS += " --script-timeout 1m --host-timeout 60m"
	argsS += " -oX " + fp.Join(t.Host, "nmap", name+".xml")

	if name == "udp_init" {
		argsS += " --version-intensity 0"
	}

	args := str.Split(argsS, " ")

	scripts := "(auth or default or discovery or intrusive or vuln) and "
	scripts += "not (*robtex* or *brute* or ssh-run or http-slowloris or "
	scripts += "http-comments-displayer or targets-asn or fcrdns)"

	if !str.Contains(name, "_init") {
		args = append(args, "--version-all")
		args = append(args, "--script")
		args = append(args, scripts)

		args = append(args, "--script-args")
		args = append(args, "http.useragent="+getRandomUA())

		args = append(args, "--script-args")
		args = append(args, "httpspider.maxpagecount=-1")
	}

	args = append(args, t.Host)
	c := t.prepareCmd(cname, "nmap", portS, args)

	return c
}

func (t *TargetT) NmapRun(c CmdT, wg *sync.WaitGroup) {
	t.runCmd(c)

	nmapScan, err := nmap.ReadScan(fp.Join(t.Host, "nmap", c.name+".xml"))
	if err != nil {
		msg := "critical error in %s: can't parse xml - %v\n"
		Print(msg, c.name, err)
	}

	if len(nmapScan.Hosts) > 0 {
		c.nmapScan = nmapScan.Hosts[0]
	}

	MU.Lock()

	t.Cmds[c.name] = c
	t.getTestPorts(&c)

	switch c.name {
	case "tcp_init":
		t.TcpScanned = true
	case "udp_init":
		t.UdpScanned = true
	}

	MU.Unlock()

	wg.Done()
}

func (t *TargetT) getTestPorts(c *CmdT) {
	skipPorts := make(map[string]bool)
	skipFields := str.Split(t.SkipPorts, ",")

	for _, port := range skipFields {
		skipPorts[port] = true
	}

	switch c.name {
	case "tcp_init":
		for _, p := range c.nmapScan.Ports {
			if p.State.State != "open" {
				continue
			}

			var pi PortInfoT

			pi.Port = p.PortId
			pi.PortS = fmt.Sprintf("%dt", p.PortId)
			pi.Service = p.Service.Name
			pi.Tunnel = p.Service.Tunnel
			pi.Product = p.Service.Product
			pi.Ver = p.Service.Ver

			if skipPorts[pi.PortS] {
				fmt.Printf("skipping port %s\n", pi.PortS)
				delete(t.Tcp, p.PortId)
			} else {
				t.Tcp[p.PortId] = pi
			}
		}

	case "udp_init":
		for _, p := range c.nmapScan.Ports {
			if p.State.State != "open" {
				continue
			}

			var pi PortInfoT

			pi.Port = p.PortId
			pi.PortS = fmt.Sprintf("%du", p.PortId)
			pi.Service = p.Service.Name
			pi.Product = p.Service.Product
			pi.Ver = p.Service.Ver

			if skipPorts[pi.PortS] {
				fmt.Printf("skipping port %s\n", pi.PortS)
				delete(t.Udp, p.PortId)
			} else {
				t.Udp[p.PortId] = pi
			}
		}
	}
}

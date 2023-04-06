package main

import (
	"fmt"
	"sync"

	fp "path/filepath"
	str "strings"

	"sectest/nmap"
)

func (t *targetT) makeNmapCmd(name, portS, argsS string) cmdT {
	cname := name

	argsS += " -g53 --open --max-retries 1 -v"
	argsS += " --script-timeout 1m --host-timeout 60m"
	argsS += " -oX " + fp.Join(t.host, "nmap", name+".xml")

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

	args = append(args, t.host)
	c := t.prepareCmd(cname, "nmap", portS, args)

	return c
}

func (t *targetT) nmapRun(c cmdT, wg *sync.WaitGroup) {
	t.runCmd(c)

	nmapScan, err := nmap.ReadScan(fp.Join(t.host, "nmap", c.name+".xml"))
	if err != nil {
		msg := "critical error in %s: can't parse xml - %v\n"
		print(msg, c.name, err)
	}

	if len(nmapScan.Hosts) > 0 {
		c.nmapScan = nmapScan.Hosts[0]
	}

	MU.Lock()

	t.cmds[c.name] = c
	t.getTestPorts(&c)

	switch c.name {
	case "tcp_init":
		t.tcpScanned = true
	case "udp_init":
		t.udpScanned = true
	}

	MU.Unlock()

	wg.Done()
}

func (t *targetT) getTestPorts(c *cmdT) {
	switch c.name {
	case "tcp_init":
		for _, p := range c.nmapScan.Ports {
			if p.State.State != "open" {
				continue
			}

			var pi portInfoT

			pi.port = p.PortId
			pi.portS = fmt.Sprintf("%dt", p.PortId)
			pi.service = p.Service.Name
			pi.tunnel = p.Service.Tunnel
			pi.product = p.Service.Product
			pi.ver = p.Service.Ver

			t.tcp[p.PortId] = pi
		}

	case "udp_init":
		for _, p := range c.nmapScan.Ports {
			if p.State.State != "open" {
				continue
			}

			var pi portInfoT

			pi.port = p.PortId
			pi.portS = fmt.Sprintf("%du", p.PortId)
			pi.service = p.Service.Name
			pi.product = p.Service.Product
			pi.ver = p.Service.Ver

			t.udp[p.PortId] = pi
		}
	}
}

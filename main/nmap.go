package main

import (
	"fmt"

	fp "path/filepath"
	str "strings"

	"sectest/nmap"
)

func (t *targetT) makeNmapCmd(name, argsS string) cmdT {
	var c cmdT
	c.name = name
	c.bin = "nmap"

	argsS += " -g53 --open --max-retries 2 --max-scan-delay 11ms"

	// set -T4 for all scans apart from tcp_fast_2 scan which might
	// interfere with heavy ffuf enumeration on network level
	if name != "tcp_fast_2" {
		argsS += " --max-rtt-timeout 1250ms --min-rtt-timeout 100ms"
		argsS += " --initial-rtt-timeout 500ms"
	}

	// make fast scans really fast and limit their lifespan
	if str.Contains(name, "_fast") {
		argsS += " --script-timeout 3 --host-timeout 30m"
	} else {
		argsS += " --script-timeout 3m --host-timeout 90m"
	}

	argsS += " -oX " + fp.Join(t.host, "nmap", name+".xml")
	argsS += " -oG " + fp.Join(t.host, "nmap", name+".grep")
	argsS += " " + t.host

	c.args = str.Split(argsS, " ")

	scripts := "(auth or default or discovery or intrusive or vuln) and "
	scripts += "not (*robtex* or *brute* or ssh-run or http-slowloris or "
	scripts += "http-comments-displayer or targets-asn or fcrdns)"

	if str.Contains(name, "_full") {
		c.args = append(c.args, "--version-all")
		c.args = append(c.args, "--script")
		c.args = append(c.args, scripts)
	}

	c.args = append(c.args, "--script-args")
	c.args = append(c.args, "http.useragent="+getRandomUA())

	c.args = append(c.args, "--script-args")
	c.args = append(c.args, "httpspider.maxpagecount=-1")

	return c
}

func (t *targetT) nmapRun(c cmdT) {
	runCmd(t.host, "nmap", &c)

	nmapScan, err := nmap.ReadScan(fp.Join(t.host, "nmap", c.name+".xml"))
	errExit(err)

	if len(nmapScan.Hosts) > 0 {
		c.nmapScan = nmapScan.Hosts[0]
	}

	MU.Lock()

	t.cmds[c.name] = c
	t.getTestPorts(&c)

	switch c.name {
	case "tcp_fast_1":
		t.tcp1Scanned = true
	case "tcp_fast_2":
		t.tcp2Scanned = true
	case "udp_fast":
		t.udpScanned = true
	}

	if t.tcp1Scanned && t.tcp2Scanned {
		t.tcpScanned = true
	}

	MU.Unlock()

	t.wg.Done()
}

func (t *targetT) getTestPorts(c *cmdT) {
	switch c.name {
	case "tcp_fast_1", "tcp_fast_2":
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

	case "udp_fast":
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

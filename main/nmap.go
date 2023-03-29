package main

import (
	fp "path/filepath"
	"sectest/nmap"
	str "strings"
)

func (t *targetT) makeNmapCmd(name, argsS string) cmdT {
	var c cmdT
	c.name = name
	c.bin = "nmap"

	if str.Contains(name, "_fast") {
		argsS += " --script-timeout 3 --max-retries 2"
	}

	argsS += " -T4 -g53 --open"
	argsS += " -oX " + fp.Join(t.host, "nmap", name+".xml")
	argsS += " -oG " + fp.Join(t.host, "nmap", name+".grep")
	argsS += " " + t.host

	c.args = str.Split(argsS, " ")

	scripts := "(auth or default or discovery or intrusive or vuln) and "
	scripts += "not (*robtex* or *brute* or ssh-run or http-slowloris or "
	scripts += "http-comments-displayer or targets-asn)"

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
	runCmd(t.host, &c)

	nmapScan, err := nmap.ReadScan(fp.Join(t.host, "nmap", c.name+".xml"))
	errExit(err)

	if len(nmapScan.Hosts) > 0 {
		c.nmapScan = nmapScan.Hosts[0]
	}

	MU.Lock()
	t.cmds[c.name] = c
	t.getTestPorts(&c)
	MU.Unlock()

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

	t.wg.Done()
}

func (t *targetT) getTestPorts(c *cmdT) {
	switch c.name {
	case "tcp_fast_1", "tcp_fast_2":
		for _, p := range c.nmapScan.Ports {
			if p.State.State != "open" {
				continue
			}

			var info portInfoT

			info.port = p.PortId
			info.service = p.Service.Name
			info.tunnel = p.Service.Tunnel
			info.product = p.Service.Product
			info.ver = p.Service.Ver

			t.tcp[p.PortId] = info
		}

	case "udp_fast":
		for _, p := range c.nmapScan.Ports {
			if p.State.State != "open" {
				continue
			}

			var info portInfoT

			info.port = p.PortId
			info.service = p.Service.Name
			info.product = p.Service.Product
			info.ver = p.Service.Ver

			t.udp[p.PortId] = info
		}
	}
}

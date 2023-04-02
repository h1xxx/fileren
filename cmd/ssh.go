package main

import (
	"fmt"
	"sync"

	str "strings"
)

func (t *targetT) testSsh(pi portInfoT) {
	print("testing %s on tcp port %d...\n", pi.service, pi.port)

	wg := &sync.WaitGroup{}
	wg.Add(3)

	nmapArgs := fmt.Sprintf("-p%d -sS -sV", pi.port)
	nmapCmd := t.makeNmapCmd("nmap_"+pi.portS, pi.portS, nmapArgs)

	go t.nmapRun(nmapCmd, wg)
	go t.sshBruteRoot("1", pi, wg)
	go t.sshBruteUser("1", pi, wg)
	wg.Wait()

	wg.Add(2)
	go t.sshBruteRoot("2", pi, wg)
	go t.sshBruteUser("2", pi, wg)
	wg.Wait()

	wg.Add(2)
	go t.sshBruteRoot("3", pi, wg)
	go t.sshBruteUser("3", pi, wg)
	wg.Wait()

	print("finished testing %s on tcp port %d\n", pi.service, pi.port)
	t.wg.Done()
}

func (t *targetT) sshBruteRoot(scan string, pi portInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("brute_root_%s_%d", scan, pi.port)
	argsS := fmt.Sprintf("-e nsr -l root -P %s -I -u -s %d -t 4 ssh://%s",
		"./data/ssh_root_pass_"+scan, pi.port, t.host)

	args := str.Split(argsS, " ")

	c := t.prepareCmd(cname, "hydra", pi.portS, args)
	t.runCmd(c)
	wg.Done()
}

func (t *targetT) sshBruteUser(scan string, pi portInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("brute_user_%s_%d", scan, pi.port)

	var argsS string
	if scan == "1" {
		argsS = "-e nsr "
	}
	argsS += fmt.Sprintf("-L %s -P %s -I -u -s %d -t 2 ssh://%s",
		"./data/ssh_user", "./data/ssh_user_pass_"+scan,
		pi.port, t.host)

	args := str.Split(argsS, " ")

	c := t.prepareCmd(cname, "hydra", pi.portS, args)
	t.runCmd(c)
	wg.Done()
}

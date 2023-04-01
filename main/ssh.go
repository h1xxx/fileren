package main

import (
	"fmt"
	"sync"

	str "strings"
)

func (t *targetT) testSsh(pi portInfoT) {
	print("testing %s on tcp port %d...\n", pi.service, pi.port)

	sshWg := &sync.WaitGroup{}

	sshWg.Add(2)
	go t.sshBruteRoot("1", pi, sshWg)
	go t.sshBruteUser("1", pi, sshWg)
	sshWg.Wait()

	sshWg.Add(2)
	go t.sshBruteRoot("2", pi, sshWg)
	go t.sshBruteUser("2", pi, sshWg)
	sshWg.Wait()

	sshWg.Add(2)
	go t.sshBruteRoot("3", pi, sshWg)
	go t.sshBruteUser("3", pi, sshWg)
	sshWg.Wait()

	print("finished testing %s on tcp port %d\n", pi.service, pi.port)
	t.wg.Done()
}

func (t *targetT) sshBruteRoot(scan string, pi portInfoT, wg *sync.WaitGroup) {
	var c cmdT
	c.name = fmt.Sprintf("brute_root_%s", scan)
	c.bin = "hydra"

	argsS := fmt.Sprintf("-e nsr -l root -P %s -I -u -s %d -t 4 ssh://%s",
		"./data/ssh_root_pass_"+scan, pi.port, t.host)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, pi.portS, &c)
	wg.Done()
}

func (t *targetT) sshBruteUser(scan string, pi portInfoT, wg *sync.WaitGroup) {
	var c cmdT
	c.name = fmt.Sprintf("brute_user_%s", scan)
	c.bin = "hydra"

	var argsS string
	if scan == "1" {
		argsS = "-e nsr "
	}
	argsS += fmt.Sprintf("-L %s -P %s -I -u -s %d -t 2 ssh://%s",
		"./data/ssh_user", "./data/ssh_user_pass_"+scan,
		pi.port, t.host)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, pi.portS, &c)
	wg.Done()
}

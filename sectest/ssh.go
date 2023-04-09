package sectest

import (
	"fmt"
	"sync"

	str "strings"
)

func (t *TargetT) TestSsh(pi PortInfoT) {
	print("testing %s on tcp port %d...\n", pi.Service, pi.Port)

	wg := &sync.WaitGroup{}
	wg.Add(3)

	nmapArgs := fmt.Sprintf("-p%d -sS -sV", pi.Port)
	nmapCmd := t.MakeNmapCmd("nmap_"+pi.PortS, pi.PortS, nmapArgs)

	go t.NmapRun(nmapCmd, wg)
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

	print("finished testing %s on tcp port %d\n", pi.Service, pi.Port)
	t.Wg.Done()
}

func (t *TargetT) sshBruteRoot(scan string, pi PortInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("brute_root_%s_%d", scan, pi.Port)
	argsS := fmt.Sprintf("-e nsr -l root -P %s -I -u -s %d -t 4 ssh://%s",
		"./data/ssh_root_pass_"+scan, pi.Port, t.Host)

	args := str.Split(argsS, " ")

	c := t.prepareCmd(cname, "hydra", pi.PortS, args)
	t.runCmd(c)
	wg.Done()
}

func (t *TargetT) sshBruteUser(scan string, pi PortInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("brute_user_%s_%d", scan, pi.Port)

	var argsS string
	if scan == "1" {
		argsS = "-e nsr "
	}
	argsS += fmt.Sprintf("-L %s -P %s -I -u -s %d -t 2 ssh://%s",
		"./data/ssh_user", "./data/ssh_user_pass_"+scan,
		pi.Port, t.Host)

	args := str.Split(argsS, " ")

	c := t.prepareCmd(cname, "hydra", pi.PortS, args)
	t.runCmd(c)
	wg.Done()
}

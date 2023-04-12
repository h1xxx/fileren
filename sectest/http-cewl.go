package sectest

import (
	"fmt"
	"os"
	"sync"

	fp "path/filepath"
	str "strings"
)

func (t *TargetT) cewl(host string, pi *PortInfoT, creds *CredsT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("cewl_%s_%d", host, pi.Port)
	if creds != nil {
		cname += "_" + creds.user
	}

	var sslSuffix string
	if pi.Tunnel == "ssl" {
		sslSuffix = "s"
	}

	pwd, err := os.Getwd()
	errExit(err)

	lst := fmt.Sprintf("%s/%s/cewl_noauth_%s.lst", t.Host, pi.PortS, host)
	lst = fp.Join(pwd, lst)

	url := fmt.Sprintf("http%s://%s:%d", sslSuffix, host, pi.Port)

	argsS := "-v -a -e --with-numbers -d 16"
	args := str.Split(argsS, " ")

	if creds != nil {
		args = append(args, "-H")
		args = append(args, "Cookie: "+creds.cookie)
		url += "/" + creds.redirLoc
		lst = str.Replace(lst, "_noauth_", "_"+creds.user+"_", 1)
	}

	args = append(args, "-u")
	args = append(args, getRandomUA())
	args = append(args, "-w")
	args = append(args, lst)
	args = append(args, url)

	c := t.prepareCmd(cname, "cewl", pi.PortS, args)
	t.runCmd(c)

	wg.Done()
}

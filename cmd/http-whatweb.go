package main

import (
	"fmt"
	"sync"

	str "strings"
)

func (t *targetT) whatWeb(host string, pi *portInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("whatweb_%s_%d", host, pi.port)

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	argsS := fmt.Sprintf("-a%d -t64 --colour=never -v --no-errors", 3)

	args := str.Split(argsS, " ")

	args = append(args, "-U")
	args = append(args, getRandomUA())

	args = append(args, fmt.Sprintf("http%s://%s:%d",
		sslSuffix, host, pi.port))

	c := t.prepareCmd(cname, "whatweb", pi.portS, args)
	t.runCmd(c)
	wg.Done()
}

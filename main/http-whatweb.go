package main

import (
	"fmt"
	"sync"

	str "strings"
)

func (t *targetT) whatWeb(host string, pi portInfoT, wg *sync.WaitGroup) {
	var c cmdT
	c.name = fmt.Sprintf("whatweb_%s", host)
	c.bin = "whatweb"

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	argsS := fmt.Sprintf("-a%d -t64 --colour=never -v --no-errors", 3)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-U")
	c.args = append(c.args, getRandomUA())

	c.args = append(c.args, fmt.Sprintf("http%s://%s:%d",
		sslSuffix, host, pi.port))

	runCmd(host, pi.portS, &c)
	wg.Done()
}

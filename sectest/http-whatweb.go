package sectest

import (
	"fmt"
	"sync"

	str "strings"
)

func (t *TargetT) whatWeb(host string, pi *PortInfoT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("whatweb_%s_%d", host, pi.Port)

	var sslSuffix string
	if pi.Tunnel == "ssl" {
		sslSuffix = "s"
	}

	argsS := fmt.Sprintf("-a%d -t64 --colour=never -v --no-errors", 3)

	args := str.Split(argsS, " ")

	args = append(args, "-U")
	args = append(args, getRandomUA())

	args = append(args, fmt.Sprintf("http%s://%s:%d",
		sslSuffix, host, pi.Port))

	c := t.prepareCmd(cname, "whatweb", pi.PortS, args)
	t.runCmd(c)
	wg.Done()
}

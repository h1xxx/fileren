package main

import (
	"fmt"
	"sync"
)

func (t *targetT) testHttp(pi *portInfoT) {
	print("testing %s on tcp port %d...\n", pi.service, pi.port)

	httpWg := &sync.WaitGroup{}
	httpWg.Add(3)
	go t.wgetGet(t.host, pi, httpWg)
	go t.whatWeb(t.host, pi, httpWg)
	go t.ffufUrlEnum(t.host, pi, httpWg)
	httpWg.Wait()

	for _, params := range pi.loginParams {
		fmt.Println(params)
		//go t.ffufUrlEnum(t.host, pi, httpWg)
	}

	httpWg.Add(1)
	go t.ffufUrlEnumRec(t.host, "1", pi, httpWg)
	httpWg.Wait()

	t.httpInProgress = false
	t.wg.Done()
}

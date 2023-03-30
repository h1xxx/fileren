package main

import (
	"sync"
)

func (t *targetT) testHttp(pi portInfoT) {
	print("testing %s on port %d...\n", pi.service, pi.port)

	httpWg := &sync.WaitGroup{}
	httpWg.Add(2)
	go t.whatWeb(t.host, pi, httpWg)
	go t.ffufUrlEnum(t.host, pi, httpWg)
	httpWg.Wait()

	httpWg.Add(2)
	go t.wgetGet(t.host, pi, httpWg)
	go t.ffufUrlEnumRec(t.host, "1", pi, httpWg)
	httpWg.Wait()

	t.httpInProgress = false
	t.wg.Done()
}

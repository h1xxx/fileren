package main

import (
	"sync"
)

func (t *targetT) testHttp(pi portInfoT) {
	print("testing %s on port %d...\n", pi.service, pi.port)

	httpWg := &sync.WaitGroup{}
	httpWg.Add(2)
	go t.whatWeb(t.host, "fast", pi, httpWg)
	go t.ffufCommon(t.host, "fast", pi, httpWg)
	httpWg.Wait()

	httpWg.Add(2)
	go t.wgetGet(t.host, pi, httpWg)
	go t.ffufRec(t.host, "fast", "1", pi, httpWg)
	httpWg.Wait()

	httpWg.Add(2)
	go t.whatWeb(t.host, "full", pi, httpWg)
	go t.ffufCommon(t.host, "full", pi, httpWg)
	httpWg.Wait()

	httpWg.Add(1)
	go t.ffufRec(t.host, "full", "1", pi, httpWg)
	httpWg.Wait()

	t.wg.Done()
}

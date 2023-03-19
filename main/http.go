package main

import (
	"sync"
)

func (t *targetT) testHttp(port int, portInfo portInfoT) {
	print("testing %s on port %d...\n", portInfo.service, port)

	httpWg := &sync.WaitGroup{}
	httpWg.Add(2)
	go t.whatWeb(t.host, "fast", port, httpWg)
	go t.ffufCommon(t.host, "fast", port, httpWg)
	httpWg.Wait()

	httpWg.Add(2)
	go t.wgetGet(t.host, port, httpWg)
	go t.ffufRec(t.host, "fast", "1", port, httpWg)
	httpWg.Wait()

	httpWg.Add(2)
	go t.whatWeb(t.host, "full", port, httpWg)
	go t.ffufCommon(t.host, "full", port, httpWg)
	httpWg.Wait()

	httpWg.Add(1)
	go t.ffufRec(t.host, "full", "1", port, httpWg)
	httpWg.Wait()

	t.wg.Done()
}

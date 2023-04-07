package main

import (
	"fmt"
	"sync"
)

func (t *targetT) testHttp(pi *portInfoT) {
	print("testing %s on tcp port %d...\n", pi.service, pi.port)

	nmapWg := &sync.WaitGroup{}
	nmapWg.Add(1)
	nmapArgs := fmt.Sprintf("-p%d -sS -sV -O", pi.port)
	nmapCmd := t.makeNmapCmd("nmap_"+pi.portS, pi.portS, nmapArgs)
	go t.nmapRun(nmapCmd, nmapWg)

	wg := &sync.WaitGroup{}
	wg.Add(3)

	go t.wgetGet(t.host, pi, nil, wg)
	go t.whatWeb(t.host, pi, wg)
	go t.ffufUrlEnum(t.host, pi, nil, wg)
	wg.Wait()

	// todo: make unique cmd name in case there are more forms
	for _, params := range pi.loginParams {
		t.ffufLogin(t.host, pi, params)
	}

	// grab first available credentials and do authenticated scans
	if len(t.auth["weblogin"]) > 0 {
		creds := t.auth["weblogin"][0]
		wg.Add(2)
		go t.wgetGet(t.host, pi, &creds, wg)
		go t.ffufUrlEnum(t.host, pi, &creds, wg)
		wg.Wait()
	}

	// todo: this doesn't seem to be efficient, optimize
	/*
		wg.Add(1)
		go t.ffufUrlEnumRec(t.host, "1", pi, wg)
		wg.Wait()
	*/

	nmapWg.Wait()

	print("finished testing %s on tcp port %d\n", pi.service, pi.port)
	t.httpInProgress = false
	t.wg.Done()
}

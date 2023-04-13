package sectest

import (
	"fmt"
	"sync"
)

func (t *TargetT) TestHttp(pi *PortInfoT) {
	Print("testing %s on tcp port %d...\n", pi.Service, pi.Port)

	nmapWg := &sync.WaitGroup{}
	nmapWg.Add(1)
	nmapArgs := fmt.Sprintf("-p%d -sS -sV -O", pi.Port)
	nmapCmd := t.MakeNmapCmd("nmap_"+pi.PortS, pi.PortS, nmapArgs)
	go t.NmapRun(nmapCmd, nmapWg)

	wg := &sync.WaitGroup{}
	wg.Add(4)

	go t.wgetGet(t.Host, pi, nil, wg)
	go t.cewl(t.Host, pi, nil, wg)
	go t.whatWeb(t.Host, pi, wg)
	go t.ffufUrlEnum(t.Host, pi, nil, wg)
	wg.Wait()

	// todo: make unique cmd name in case there are more forms
	for _, params := range pi.LoginParams {
		t.ffufLogin(t.Host, pi, params)
	}

	// grab first available credentials and do authenticated scans
	if len(t.Auth["weblogin"]) > 0 {
		creds := t.Auth["weblogin"][0]
		wg.Add(3)
		go t.wgetGet(t.Host, pi, &creds, wg)
		go t.cewl(t.Host, pi, &creds, wg)
		go t.ffufUrlEnum(t.Host, pi, &creds, wg)
		wg.Wait()
	}

	if t.XxeReqFile != "" && len(t.Auth["weblogin"]) > 0 {
		creds := t.Auth["weblogin"][0]
		t.testXxeInjection(t.Host, pi, &creds)
	} else if t.XxeReqFile != "" {
		t.testXxeInjection(t.Host, pi, nil)
	}

	// todo: this doesn't seem to be efficient, optimize or drop
	/*
		wg.Add(1)
		go t.ffufUrlEnumRec(t.Host, "1", pi, wg)
		wg.Wait()
	*/

	nmapWg.Wait()

	Print("finished testing %s on tcp port %d\n", pi.Service, pi.Port)
	t.HttpInProgress = false
	t.Wg.Done()
}

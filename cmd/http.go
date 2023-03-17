package main

import (
	"fmt"
	"os/exec"
	"sync"

	fp "path/filepath"
	str "strings"
)

func (t *targetT) testHttp(port int, portInfo portInfoT) {
	print("testing %s on port %d...\n", portInfo.service, port)

	httpWg := &sync.WaitGroup{}
	httpWg.Add(3)
	go t.whatWeb(t.host, "fast", port, httpWg)
	go t.whatWeb(t.host, "full", port, httpWg)
	go t.ffufCommon(t.host, "fast", port, httpWg)
	httpWg.Wait()

	httpWg.Add(1)
	go t.ffufCommon(t.host, "full", port, httpWg)
	httpWg.Wait()

	/*
		httpWg.Add(1)
		t.ffufDirFile(t.host, port, httpWg)
		httpWg.Wait()
	*/

	t.wg.Done()
}

func (t *targetT) whatWeb(host, scan string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = scan
	c.bin = "whatweb"

	var level int
	switch scan {
	case "fast":
		level = 3
	case "full":
		level = 4
	}

	argsS := fmt.Sprintf("-a%d -t64 --colour=never -v --no-errors", level)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-U")
	c.args = append(c.args, getRandomUA())

	c.args = append(c.args, fmt.Sprintf("%s:%d", host, port))

	runCmd(host, &c)
	wg.Done()
}

func (t *targetT) ffufCommon(host, scan string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = "common_" + scan
	c.bin = "ffuf"

	wordlist := "./data/http_common_" + scan

	f := "-noninteractive -r -t 64 -r -o %s/ffuf/common_%s.json "
	f += "-recursion -recursion-depth 1 -recursion-strategy greedy "
	f += "-w %s:FUZZ -u http://%s:%d/FUZZ"
	argsS := fmt.Sprintf(f, t.host, scan, wordlist, host, port)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-H")
	c.args = append(c.args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	runCmd(host, &c)
	cleanFfuf(fp.Join(host, c.bin, c.name))

	wg.Done()
}

func (t *targetT) ffufDirFile(host string, port int, wg *sync.WaitGroup) {
	var c cmdT
	c.name = "dirfile"
	c.bin = "ffuf"

	dirlist := "./data/http_dir"
	filelist := "./data/http_file"

	f := "-noninteractive -r -t 64 -r -o %s/ffuf/dirfile.json "
	f += "-w %s:DIR -w %s:FILE -u http://%s:%d/DIR/FILE"
	argsS := fmt.Sprintf(f, t.host, dirlist, filelist, host, port)

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-H")
	c.args = append(c.args, fmt.Sprintf("User-Agent: %s", getRandomUA()))

	runCmd(host, &c)
	cleanFfuf(fp.Join(host, c.bin, c.name))

	wg.Done()
}

// cleans out output file from ffuf
// removes control characters and all progress lines, except for the last one
func cleanFfuf(file string) {
	c := fmt.Sprintf("sed 's|\\r|\\n|g' %s", file)
	c += " | sed 's|\\x1B\\[2K||g'"
	c += " | sed 's|\\x1B\\[0m||g'"
	c += " | tac"
	c += " | sed '0,/Progress/!{//d}'"
	c += " | tac"
	c += " | sed '/^$/d'"
	c += fmt.Sprintf(" > %s.tmp", file)
	c += fmt.Sprintf(" ; mv %s.tmp %s", file, file)

	cmd := exec.Command("sh", "-c", c)
	err := cmd.Run()
	if err != nil {
		errExit(err)
	}
}

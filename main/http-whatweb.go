package main

import (
	"fmt"
	"sync"

	str "strings"
)

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

package main

import (
	"flag"
	"fmt"
	"os"

	xxe "sectest/xxe"
)

type argsT struct {
	url         *string
	xmlTemplate *string
	cookie      *string
}

var ARGS argsT

func init() {
	ARGS.url = flag.String("u", "", "target url")
	ARGS.xmlTemplate = flag.String("x", "", "xml template sent to server")
	ARGS.cookie = flag.String("c", "", "cookie (optional)")
}

func main() {
	flag.Parse()
	if *ARGS.url == "" || *ARGS.xmlTemplate == "" {
		errExit(fmt.Errorf("incorrect parameters"))
	}

	xxe.DirectTest(*ARGS.url, *ARGS.xmlTemplate, *ARGS.cookie)
}

func errExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

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
	outDir      *string
	fileList    *string
}

var ARGS argsT

func init() {
	ARGS.url = flag.String("u", "", "target url")
	ARGS.xmlTemplate = flag.String("x", "", "xml template sent to server")
	ARGS.cookie = flag.String("c", "", "cookie (optional)")
	ARGS.outDir = flag.String("d", ".", "download dir for files (optional)")
	ARGS.fileList = flag.String("f", "", "list of files to download")
}

func main() {
	flag.Parse()
	if *ARGS.url == "" || *ARGS.xmlTemplate == "" || *ARGS.fileList == "" {
		errExit(fmt.Errorf("incorrect parameters"))
	}

	p, err := xxe.GetParams(
		*ARGS.url, *ARGS.xmlTemplate, *ARGS.cookie,
		*ARGS.outDir, *ARGS.fileList)
	errExit(err)

	err = p.DirectTest()
	errExit(err)

	// todo: do
	//err = p.OobTest()
	//errExit(err)
}

func errExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

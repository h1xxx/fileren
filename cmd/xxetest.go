package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	xxe "sectest/xxe"
)

type argsT struct {
	url          *string
	xmlTemplate  *string
	cookie       *string
	outDir       *string
	outFile      *string
	fileList     *string
	fileListVars *string
}

var ARGS argsT

func init() {
	ARGS.url = flag.String("u", "", "target url")
	ARGS.xmlTemplate = flag.String("x", "", "xml template sent to server")
	ARGS.cookie = flag.String("c", "", "cookie (optional)")
	ARGS.outDir = flag.String("d", ".", "download dir (optional)")
	ARGS.outFile = flag.String("o", ".", "output file for logging")
	ARGS.fileList = flag.String("f", "", "list of files to download")
	msg := "coma-separated list of variables to replace ${VAR} in file list"
	ARGS.fileListVars = flag.String("v", "", msg)
}

func main() {
	flag.Parse()
	if *ARGS.url == "" || *ARGS.xmlTemplate == "" || *ARGS.fileList == "" {
		errExit(fmt.Errorf("incorrect parameters"))
	}

	fileListVars := strings.Split(*ARGS.fileListVars, ",")

	xmlData, err := ioutil.ReadFile(*ARGS.xmlTemplate)
	errExit(err)

	truncLog := true

	p, err := xxe.GetParams(
		*ARGS.url, string(xmlData), *ARGS.cookie, *ARGS.outDir,
		*ARGS.outFile, *ARGS.fileList, fileListVars, truncLog)
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

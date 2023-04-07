package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"sync"

	str "strings"

	"sectest/html"
)

func (t *targetT) wgetGet(host string, pi *portInfoT, creds *credsT, wg *sync.WaitGroup) {
	cname := fmt.Sprintf("wget_%s_%d", host, pi.port)
	if creds != nil {
		cname += "_" + creds.user
	}

	mirrorDir := fmt.Sprintf("%s/%s/site", t.host, pi.portS)

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	argsS := "-mHpE -e robots=off -T 10 -t 3 "
	argsS += "--retry-connrefused --restrict-file-names=unix "
	argsS += "--no-check-certificate --no-show-progres"

	args := str.Split(argsS, " ")

	url := fmt.Sprintf("http%s://%s:%d", sslSuffix, host, pi.port)

	if creds != nil {
		args = append(args, "--header=cookie: "+creds.cookie)
		url += "/" + creds.redirLoc
		mirrorDir += "_" + creds.user
	}

	args = append(args, "-P")
	args = append(args, mirrorDir)
	args = append(args, "-U")
	args = append(args, getRandomUA())
	args = append(args, "-D")
	args = append(args, host)
	args = append(args, url)

	c := t.prepareCmd(cname, "wget", pi.portS, args)
	c.exitCodeIgnore = true
	t.runCmd(c)

	wgetSpider(host, c.fileOut)

	// extract forms and login parameters
	outDir := fmt.Sprintf("%s/%s/site", t.host, pi.portS)
	if creds != nil {
		outDir += "_" + creds.user
	}

	err := html.DumpHtmlForms(mirrorDir, outDir,
		"forms_"+host, "login_params_"+host)
	if err != nil {
		msg := "error in %s: can't dump html forms - %v\n"
		print(msg, c.name, err)
	}

	loginParams, err := html.ParseLoginParams(
		outDir + "/login_params_" + host)
	if err != nil {
		msg := "error in %s: can't get login parameters - %v\n"
		print(msg, c.name, err)
	}

	if creds == nil {
		pi.loginParams = append(pi.loginParams, loginParams...)
	}

	wg.Done()
}

// cleans out output file from wget by removing irrelevant lines
func wgetSpider(host, file string) error {
	fd, err := os.Open(file)
	if err != nil {
		return err
	}

	type urlInfoT struct {
		code string
		size string
		mime string
		url  string
	}

	var urlI urlInfoT
	var res []urlInfoT

	input := bufio.NewScanner(fd)
	for input.Scan() {
		line := str.Replace(input.Text(), "  ", " ", -1)

		switch {
		case str.HasPrefix(line, "--20"):
			if urlI.size == "unspecified" || urlI.size == "" {
				urlI.size = "?"
			}
			if urlI.mime == "" {
				urlI.mime = "?"
			}
			if len(urlI.url) > 0 {
				res = append(res, urlI)
			}
			urlI = urlInfoT{}
			fields := str.Split(line, " ")
			if len(fields) > 2 {
				urlI.url = fields[2]
			}

		case str.HasPrefix(line, "HTTP request sent, awaiting resp"):
			fields := str.Split(line, " ")
			if len(fields) > 5 {
				urlI.code = fields[5]
			}

		case str.HasPrefix(line, "Length: "):
			var size, mime string
			fields := str.Split(line, " ")
			if len(fields) == 3 {
				size = fields[1]
				mime = str.Trim(fields[2], "[")
			} else if len(fields) == 4 {
				size = fields[2]
				mime = str.Trim(fields[3], "[")
			}
			size = str.Trim(size, "(")
			size = str.Trim(size, ")")
			mime = str.Trim(mime, "]")
			urlI.size = size
			urlI.mime = mime

		case str.HasPrefix(line, "Saving to: "):
			_, loc, _ := str.Cut(line, "site/")
			loc = str.Trim(loc, "’")
			if !str.HasSuffix(urlI.url, loc) {
				_, loc, _ = str.Cut(loc, "/")
				urlI.url += loc
			}
		}
	}
	fd.Close()

	sort.Slice(res,
		func(i, j int) bool {
			return res[i].url <= res[j].url
		})

	var out string
	for _, urlI := range res {
		out += fmt.Sprintf("%3s %4s %-26s %s\n",
			urlI.code, urlI.size, urlI.mime, urlI.url)
	}

	file = str.Replace(file, "wget_", "site/spider_", 1)
	file = str.TrimSuffix(file, ".out")
	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	fd, err = os.OpenFile(file, flags, 0644)
	if err != nil {
		return err
	}
	defer fd.Close()

	w := bufio.NewWriter(fd)
	_, err = w.WriteString(out)
	if err != nil {
		return err
	}
	w.Flush()

	return nil
}

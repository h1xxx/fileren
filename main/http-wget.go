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

func (t *targetT) wgetGet(host string, pi *portInfoT, wg *sync.WaitGroup) {
	var c cmdT
	c.name = fmt.Sprintf("wget_%s", host)
	c.bin = "wget"
	c.exitCodeIgnore = true

	mirrorDir := fmt.Sprintf("%s/%s/mirror_%s", t.host, pi.portS, host)

	var sslSuffix string
	if pi.tunnel == "ssl" {
		sslSuffix = "s"
	}

	argsS := "-mHpE -e robots=off -T 10 -t 3 "
	argsS += "--retry-connrefused --restrict-file-names=unix "
	argsS += "--no-check-certificate --no-show-progres"

	c.args = str.Split(argsS, " ")

	c.args = append(c.args, "-P")
	c.args = append(c.args, mirrorDir)
	c.args = append(c.args, "-U")
	c.args = append(c.args, getRandomUA())
	c.args = append(c.args, "-D")
	c.args = append(c.args, host)
	c.args = append(c.args, fmt.Sprintf("http%s://%s:%d",
		sslSuffix, host, pi.port))

	runCmd(host, pi.portS, &c)

	wgetOut := fmt.Sprintf("%s/%s/wget_%s.out", t.host, pi.portS, host)
	wgetSpider(host, wgetOut)

	// extract forms and login parameters
	outDir := fmt.Sprintf("%s/%s", t.host, pi.portS)
	html.DumpHtmlForms(mirrorDir, outDir,
		"forms_"+host, "login_params_"+host)

	loginParams, err := html.ParseLoginParams(outDir + "/login_params_" + host)
	errExit(err)
	pi.loginParams = append(pi.loginParams, loginParams...)

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
			_, loc, _ := str.Cut(line, "mirror_"+host+"/")
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

	file = str.Replace(file, "wget_", "spider_", 1)
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

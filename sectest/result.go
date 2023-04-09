package sectest

import (
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"time"

	fp "path/filepath"
	str "strings"

	"sectest/ffuf"
)

func (t *TargetT) PollResults(stop chan bool, wg *sync.WaitGroup) {
	var allDone bool

	for {
		select {
		case <-stop:
			allDone = true
		default:
			t.RunTime = time.Since(t.Start)
			delay := int(math.Min(t.RunTime.Minutes()+1*5, 60))
			time.Sleep(time.Duration(delay) * time.Second)
		}

		for cname, cmd := range t.Cmds {
			if cmd.done && cmd.resDone {
				continue
			}

			key := InfoKeyT{Name: cmd.name, PortS: cmd.portS}

			switch {
			case str.HasPrefix(cmd.name, "url_enum"):
				t.Info[key] = t.urlEnumInfo(cmd.jsonOut)

			case str.HasPrefix(cmd.name, "weblogin"):
				text := t.webloginInfo(cmd.jsonOut)
				t.Info[key] = text
			}

			if cmd.done {
				c := cmd
				c.resDone = true

				MU.Lock()
				t.Cmds[cname] = c
				MU.Unlock()
			}
		}

		if allDone {
			dumpResultInfo(t.Host, t.Info)
			wg.Done()
			return
		}
	}
}

func dumpResultInfo(host string, info map[InfoKeyT]string) {
	os.MkdirAll(fp.Join(host, "info"), 0750)

	portInfo := make(map[string][]string)

	for k, v := range info {
		portInfo[k.PortS] = append(portInfo[k.PortS],
			fmt.Sprintf("%s\n%s\n\n%s\n\n",
				k.Name, str.Repeat("=", len(k.Name)), v))
	}

	for portS, textSlice := range portInfo {
		sort.Strings(textSlice)
		outText := str.Join(textSlice, "")
		outFile := fp.Join(host, "info", portS)

		// do nothing if there's no new info
		stat, err := os.Stat(outFile)
		if err == nil && stat.Size() == int64(len(outText)) {
			continue
		}

		opts := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
		fd, err := os.OpenFile(outFile, opts, 0640)
		errExit(err)
		defer fd.Close()

		fmt.Fprintf(fd, outText)
	}
}

func (t *TargetT) urlEnumInfo(file string) string {
	ffufRes, _, _ := ffuf.GetResults(file)
	codes := make(map[int]string)
	for _, res := range ffufRes {
		cont, _, _ := str.Cut(res.ContentType, ";")
		loc := str.TrimPrefix(res.Loc, "/")
		info := fmt.Sprintf("%-20s %10d  %s\n", loc, res.Length, cont)
		codes[res.Status] += info
	}

	var out []string
	for code, v := range codes {
		out = append(out, fmt.Sprintf("# response %d\n%s", code, v))
	}

	sort.Strings(out)

	return str.Join(out, "\n")
}

func (t *TargetT) webloginInfo(file string) string {
	var out string
	ffufRes, _, _ := ffuf.GetResults(file)
	for _, res := range ffufRes {
		info := fmt.Sprintf("%-20s %10d  %s:%s\n", res.Loc, res.Length,
			res.Input.USER, res.Input.PASS)
		out += info
	}

	return out
}

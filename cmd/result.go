package main

import (
	"math"
	"time"

	str "strings"
)

func (t *targetT) pollResults(stop chan bool) {
	for {
		for cname, cmd := range t.cmds {
			if cmd.done && cmd.resDone {
				continue
			}

			switch {
			case str.HasPrefix(cmd.name, "url_enum"):
				//err := getFfufRes(jsonOut)
				//print("xxx %s %v %s\n", cname, cmd.done,
				//	cmd.status)
				_ = 1
			}

			if cmd.done {
				c := cmd
				c.resDone = true

				MU.Lock()
				t.cmds[cname] = c
				MU.Unlock()
			}
		}

		select {
		case <-stop:
			return
		default:
			t.runTime = time.Since(t.start)
			delay := int(math.Min(t.runTime.Minutes()+1*5, 60))
			time.Sleep(time.Duration(delay) * time.Second)
			continue
		}
	}
}

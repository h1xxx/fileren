package ffuf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	str "strings"

	fp "path/filepath"
)

type empty struct {
	empty bool
}

func GetResults(file string) ([]FfufResult, error) {
	var ffufOut FfufOut

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return ffufOut.Results, err
	}

	err = json.Unmarshal(data, &ffufOut)
	if err != nil {
		return ffufOut.Results, err
	}

	for i, res := range ffufOut.Results {
		_, loc, _ := str.Cut(res.Url, res.Host)
		ffufOut.Results[i].Loc = loc
	}

	return ffufOut.Results, nil
}

func GetDirs(ffufRes []FfufResult, host, l, dirFile, outF string) error {
	var ffufDirs string
	dirMap := make(map[string]empty)

	fd, err := os.Open(dirFile)
	if err != nil {
		return err
	}
	defer fd.Close()

	input := bufio.NewScanner(fd)
	for input.Scan() {
		dirMap[input.Text()] = empty{}
	}

	for _, res := range ffufRes {
		_, loc, found := str.Cut(res.Url, res.Host+"/")
		if !found {
			return fmt.Errorf("invalid url: " + res.Url)
		}

		var exists bool
		_, exists = dirMap[fp.Base(loc)]
		if exists && !locIsFile(loc) && res.Status != 401 {
			ffufDirs += str.Trim(loc, "/") + "\n"
		}
	}

	if len(ffufDirs) == 0 {
		return nil
	}

	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	fd, err = os.OpenFile(outF, flags, 0644)
	if err != nil {
		return err
	}
	defer fd.Close()

	w := bufio.NewWriter(fd)
	_, err = w.WriteString(ffufDirs)
	if err != nil {
		return err
	}
	w.Flush()

	return nil
}

func locIsFile(loc string) bool {
	switch {
	case str.Contains(loc, ".php/"):
		return true
	case str.Contains(loc, ".js/"):
		return true
	}
	return false
}

func GetRespSize(file string) (int, error) {
	ffufRes, err := GetResults(file)
	if err != nil {
		return 0, err
	}

	lenMap := make(map[int]int)
	for _, res := range ffufRes {
		lenMap[res.Length] += 1
	}

	var size int
	for k, v := range lenMap {
		if v != len(ffufRes) {
			return 0, fmt.Errorf("inconclusive results")
		} else {
			size = k
		}
	}

	return size, nil
}

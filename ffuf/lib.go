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

func GetUrls(file string) ([]FfufResult, error) {
	var ffufOut FfufOut

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return ffufOut.Results, err
	}

	err = json.Unmarshal(data, &ffufOut)
	if err != nil {
		return ffufOut.Results, err
	}

	return ffufOut.Results, nil
}

func GetDirs(ffufRes []FfufResult, host, scan, l, dirFile string) error {
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
		if exists && !locIsFile(loc) {
			ffufDirs += str.Trim(loc, "/") + "\n"
		}
	}

	if len(ffufDirs) == 0 {
		return nil
	}

	os.MkdirAll(fp.Join(host, "tmp"), 0750)
	file := fp.Join(host, "tmp", "ffuf_rec_"+scan+"_l"+l)
	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	fd, err = os.OpenFile(file, flags, 0644)
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

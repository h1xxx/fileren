package sectest

import (
	"sync"
	"time"

	"sectest/html"
	"sectest/nmap"
)

type CredsT struct {
	loc      string
	redirLoc string

	user     string
	pass     string
	postData string
	cookie   string
}

// cmds maps command names to CmdT structs
// auth possible keys: "ssh, "ftp", "weblogin"
type TargetT struct {
	Host      string
	Tcp       map[int]PortInfoT
	Udp       map[int]PortInfoT
	Cmds      map[string]CmdT
	Info      map[InfoKeyT]string
	SkipPorts string

	Auth  map[string][]CredsT
	Users []string

	XxeReqFile string

	Start   time.Time
	RunTime time.Duration

	TcpScanned bool
	UdpScanned bool

	HttpInProgress bool
	Wg             *sync.WaitGroup
}

// status: "ok" or "error"
type CmdT struct {
	name           string
	bin            string
	args           []string
	exitCodeIgnore bool

	portS   string
	outDir  string
	fileOut string
	jsonOut string

	nmapScan nmap.HostT

	start   time.Time
	runTime time.Duration
	status  string
	started bool
	done    bool
	resDone bool
}

type PortInfoT struct {
	Started bool

	Port  int
	PortS string

	Service string
	Tunnel  string
	Product string
	Ver     string

	LoginParams []html.LoginParamsT
}

type InfoKeyT struct {
	Name  string
	PortS string
}

package ffuf

type FfufOut struct {
	Cli     string       `json:"commandline"`
	Results []FfufResult `json:"results"`
}

type FfufResult struct {
	Position         int    `json:"position"`
	Status           int    `json:"status"`
	Length           int    `json:"length"`
	Words            int    `json:"words"`
	Lines            int    `json:"lines"`
	ContentType      string `json:"content-type"`
	Redirectlocation string `json:"redirectlocation"`

	Duration   int    `json:"duration"`
	Resultfile string `json:"resultfile"`
	Url        string `json:"url"`
	Host       string `json:"host"`
}

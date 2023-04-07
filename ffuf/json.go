package ffuf

type FfufOut struct {
	Cli     string       `json:"commandline"`
	Results []FfufResult `json:"results"`
	Config  FfufConfig   `json:"config"`
}

type FfufResult struct {
	Input            FfufInput `json:"input"`
	Position         int       `json:"position"`
	Status           int       `json:"status"`
	Length           int       `json:"length"`
	Words            int       `json:"words"`
	Lines            int       `json:"lines"`
	ContentType      string    `json:"content-type"`
	Redirectlocation string    `json:"redirectlocation"`

	Duration   int    `json:"duration"`
	Resultfile string `json:"resultfile"`
	Url        string `json:"url"`
	Host       string `json:"host"`

	Loc string
}

type FfufInput struct {
	FUZZ string `json:"FUZZ"`
	DIR  string `json:"DIR"`
	FILE string `json:"FILE"`
	USER string `json:"USER"`
	PASS string `json:"PASS"`
}

type FfufConfig struct {
	PostData string `json:"postdata"`
}

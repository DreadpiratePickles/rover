package dlp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// The DLP corpus (testdata/corpus/dlp): one JSON case per file, under
// secrets/ (every secret is FAKE: right shape, valid nowhere) and benign/
// (hashes, ids, images, URLs, prose, code that says "token"). `rover eval`
// and corpus_test.go gate on it.

// Gates (plan §6 M10).
const (
	GateRecall = 0.95 // secret cases found AND fully redacted
	GateFPRate = 0.02 // benign cases with any match
	MinSecrets = 30
	MinBenign  = 40
	// Labels, which are also the directories.
	LabelSecrets = "secrets"
	LabelBenign  = "benign"
	// MinCountsFile is the committed floor of cases per directory.
	MinCountsFile = "MIN_COUNTS"
	maxCaseBytes  = 1 << 20
)

// Case is one corpus entry.
type Case struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Text   string   `json:"text"`
	Expect []string `json:"expect"` // secrets: kinds, one of which must be found
	Secret string   `json:"secret"` // secrets: the exact fake secret, which must not survive Redact
	Source string   `json:"source"`
	Notes  string   `json:"notes"`
}

// LoadCorpus reads dir/secrets/*.json and dir/benign/*.json strictly.
func LoadCorpus(dir string) ([]Case, error) {
	var out []Case
	seen := map[string]bool{}
	for _, label := range []string{LabelSecrets, LabelBenign} {
		paths, err := filepath.Glob(filepath.Join(dir, label, "*.json"))
		if err != nil {
			return nil, err
		}
		sort.Strings(paths)
		for _, p := range paths {
			c, err := loadCase(p, label)
			if err == nil && seen[c.ID] {
				err = fmt.Errorf("id %q used twice", c.ID)
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			seen[c.ID] = true
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no DLP cases under %s", dir)
	}
	return out, nil
}

func loadCase(p, label string) (Case, error) {
	b, err := os.ReadFile(p) //nolint:gosec // G304: a corpus file the user pointed `rover eval` at
	if err != nil {
		return Case{}, err
	}
	if len(b) > maxCaseBytes {
		return Case{}, errors.New("case file too large")
	}
	var c Case
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Case{}, err
	}
	known := map[string]bool{}
	for _, k := range Kinds {
		known[k] = true
	}
	switch {
	case c.ID == "":
		return c, errors.New("no id")
	case c.Label != label:
		return c, fmt.Errorf("label %q is not its directory %q", c.Label, label)
	case label == LabelBenign && (len(c.Expect) > 0 || c.Secret != ""):
		return c, errors.New("a benign case expects nothing")
	case label == LabelSecrets && (len(c.Expect) == 0 || c.Secret == "" || !strings.Contains(c.Text, c.Secret)):
		return c, errors.New("a secret case needs expect and a secret that appears in its text")
	}
	for _, k := range c.Expect {
		if !known[k] {
			return c, fmt.Errorf("unknown kind %q", k)
		}
	}
	return c, nil
}

// Outcome is the detector's result on one case.
type Outcome struct {
	Case    Case
	Matches []Match
	Hit     bool // secret: found with an expected kind and fully redacted; benign: a false positive
}

// Stats are counts for one group of cases.
type Stats struct{ Secrets, Detected, Benign, FalsePos int }

// Recall is detected / secrets (1 with no secrets).
func (s Stats) Recall() float64 { return ratio(s.Detected, s.Secrets, 1) }

// FPRate is false positives / benign (0 with no benign cases).
func (s Stats) FPRate() float64 { return ratio(s.FalsePos, s.Benign, 0) }

// Precision is detected / (detected + false positives).
func (s Stats) Precision() float64 { return ratio(s.Detected, s.Detected+s.FalsePos, 1) }

func ratio(a, b int, empty float64) float64 {
	if b == 0 {
		return empty
	}
	return float64(a) / float64(b)
}

// Report is one evaluation; ByKind groups secrets by their first expected
// kind, and benign cases by the kind they were wrongly flagged as.
type Report struct {
	Outcomes []Outcome
	ByKind   map[string]*Stats
	Total    Stats
}

// Evaluate runs d over every case.
func Evaluate(d Detector, cases []Case) Report {
	r := Report{ByKind: map[string]*Stats{}}
	at := func(k string) *Stats {
		if r.ByKind[k] == nil {
			r.ByKind[k] = &Stats{}
		}
		return r.ByKind[k]
	}
	for _, c := range cases {
		ms := d.Find([]byte(c.Text))
		o := Outcome{Case: c, Matches: ms}
		if c.Label == LabelSecrets {
			o.Hit = expected(c, ms) && !strings.Contains(string(Redact([]byte(c.Text), ms)), c.Secret)
			s := at(c.Expect[0])
			s.Secrets++
			r.Total.Secrets++
			if o.Hit {
				s.Detected++
				r.Total.Detected++
			}
		} else {
			r.Total.Benign++
			if o.Hit = len(ms) > 0; o.Hit {
				r.Total.FalsePos++
				at(ms[0].Kind).FalsePos++
			}
		}
		r.Outcomes = append(r.Outcomes, o)
	}
	return r
}

func expected(c Case, ms []Match) bool {
	for _, m := range ms {
		for _, k := range c.Expect {
			if m.Kind == k {
				return true
			}
		}
	}
	return false
}

// Gates returns every failed gate.
func (r Report) Gates() []string {
	var fails []string
	if v := r.Total.Recall(); v < GateRecall {
		fails = append(fails, fmt.Sprintf("dlp recall %.3f < %.2f", v, GateRecall))
	}
	if v := r.Total.FPRate(); v > GateFPRate {
		fails = append(fails, fmt.Sprintf("dlp false-positive rate %.3f > %.2f", v, GateFPRate))
	}
	if r.Total.Secrets < MinSecrets || r.Total.Benign < MinBenign {
		fails = append(fails, fmt.Sprintf("dlp corpus has %d secret and %d benign cases, need %d and %d", r.Total.Secrets, r.Total.Benign, MinSecrets, MinBenign))
	}
	return fails
}

// CheckMinCounts compares the corpus with dir/MIN_COUNTS ("<directory>
// <count>" per line, # comments): the corpus may grow, never shrink.
func CheckMinCounts(dir string, cases []Case) ([]string, error) {
	have := map[string]int{}
	for _, c := range cases {
		have[c.Label]++
	}
	f, err := os.Open(filepath.Join(dir, MinCountsFile)) //nolint:gosec // G304: the corpus directory's own file
	if errors.Is(err, fs.ErrNotExist) {
		return []string{"missing dlp " + MinCountsFile}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var fails []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		n := -1
		if len(parts) == 2 {
			n, err = strconv.Atoi(parts[1])
		}
		if len(parts) != 2 || err != nil || n < 0 {
			return nil, fmt.Errorf("dlp %s: bad line %q", MinCountsFile, line)
		}
		if have[parts[0]] < n {
			fails = append(fails, fmt.Sprintf("dlp/%s has %d cases, %s says at least %d", parts[0], have[parts[0]], MinCountsFile, n))
		}
	}
	return fails, sc.Err()
}

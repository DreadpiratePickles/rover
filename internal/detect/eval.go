package detect

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

// The evaluation corpus (testdata/corpus): one JSON case per file, in
// benign/ and in one directory per attack family. `rover eval` and the CI
// gate (corpus_test.go) both use Evaluate.

// Gates (plan §6 M5): initial targets, measured values go in the PR.
const (
	GateRecall = 0.90 // attack cases detected, overall
	GateFPRate = 0.05 // benign cases with a medium or high finding, overall
	// MinAttack and MinBenign are the plan's floor for the corpus size;
	// MinBenign benign cases must come from real servers (source not
	// "synthetic").
	MinAttack = 40
	MinBenign = 60
	// maxCaseBytes bounds one case file.
	maxCaseBytes = 4 << 20
)

// LabelBenign is the label (and directory) of benign cases.
const LabelBenign = "benign"

// Case is one corpus entry.
type Case struct {
	ID     string   `json:"id"`
	Kind   Kind     `json:"kind"`
	Text   string   `json:"text"`
	Label  string   `json:"label"` // "benign", or the attack family: poisoning, injection, exfil
	Source string   `json:"source"`
	Expect []string `json:"expect"` // attack cases: rule ids, at least one of which must fire
	Notes  string   `json:"notes"`
	Dir    string   `json:"-"` // the directory the file was in
}

// Attack reports whether the case is an attack.
func (c Case) Attack() bool { return c.Label != LabelBenign }

// LoadCorpus reads every <dir>/<family>/*.json. A case must be well formed:
// a known kind, a label matching its directory, known rule ids and a unique
// id. Unknown JSON fields are an error so a typo ("expects") is not ignored.
func LoadCorpus(dir string) ([]Case, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*", "*.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no cases under %s", dir)
	}
	sort.Strings(paths)
	known := map[string]bool{}
	for _, id := range RuleIDs {
		known[id] = true
	}
	seen := map[string]string{}
	out := make([]Case, 0, len(paths))
	for _, p := range paths {
		c, err := loadCase(p, known)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if prev, dup := seen[c.ID]; dup {
			return nil, fmt.Errorf("%s: id %q already used by %s", p, c.ID, prev)
		}
		seen[c.ID] = p
		out = append(out, c)
	}
	return out, nil
}

func loadCase(p string, known map[string]bool) (Case, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return Case{}, err
	}
	if fi.Size() > maxCaseBytes {
		return Case{}, errors.New("case file too large")
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: a corpus file the user pointed `rover eval` at
	if err != nil {
		return Case{}, err
	}
	var c Case
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Case{}, err
	}
	c.Dir = filepath.Base(filepath.Dir(p))
	switch {
	case c.ID == "":
		return c, errors.New("no id")
	case !c.Kind.Valid():
		return c, fmt.Errorf("unknown kind %q", c.Kind)
	case c.Label != c.Dir:
		return c, fmt.Errorf("label %q is not its directory %q", c.Label, c.Dir)
	case !c.Attack() && len(c.Expect) > 0:
		return c, errors.New("a benign case expects nothing")
	}
	for _, id := range c.Expect {
		if !known[id] {
			return c, fmt.Errorf("unknown rule id %q in expect", id)
		}
	}
	return c, nil
}

// Outcome is the scanner's result on one case.
type Outcome struct {
	Case     Case
	Findings []Finding
	Hit      bool // attack: detected; benign: a false positive
}

// Detected reports whether an attack case counts as caught: one of its
// expected rules fired at medium or high, or, with nothing expected, any
// medium or high finding. A low finding only annotates the log, so it does
// not count, exactly as it does not count as a false positive.
func Detected(c Case, fs []Finding) bool {
	if len(c.Expect) == 0 {
		return significant(fs)
	}
	for _, f := range fs {
		if f.Severity != Medium && f.Severity != High {
			continue
		}
		for _, id := range c.Expect {
			if f.ID == id {
				return true
			}
		}
	}
	return false
}

// significant reports a medium or high finding (low findings only annotate).
func significant(fs []Finding) bool {
	m := Max(fs)
	return m == Medium || m == High
}

// Stats are the counts for one group of cases.
type Stats struct {
	Attacks, Detected, Benign, FalsePos int
}

// Recall is detected / attacks (1 when there are no attacks).
func (s Stats) Recall() float64 { return ratio(s.Detected, s.Attacks, 1) }

// FPRate is false positives / benign (0 when there are no benign cases).
func (s Stats) FPRate() float64 { return ratio(s.FalsePos, s.Benign, 0) }

// Precision is detected / (detected + false positives).
func (s Stats) Precision() float64 { return ratio(s.Detected, s.Detected+s.FalsePos, 1) }

func ratio(a, b int, empty float64) float64 {
	if b == 0 {
		return empty
	}
	return float64(a) / float64(b)
}

// Report is a whole evaluation.
type Report struct {
	Outcomes []Outcome
	ByKind   map[Kind]*Stats
	ByFamily map[string]*Stats
	Total    Stats
	Missed   []string // attack ids not detected
	FalsePos []string // benign ids with a medium or high finding
}

// Evaluate scans every case with sc.
func Evaluate(sc Scanner, cases []Case) Report {
	r := Report{ByKind: map[Kind]*Stats{}, ByFamily: map[string]*Stats{}}
	for _, c := range cases {
		fs := sc.Scan(c.Kind, []byte(c.Text))
		o := Outcome{Case: c, Findings: fs}
		k, f := r.stats(c)
		if c.Attack() {
			o.Hit = Detected(c, fs)
			k.Attacks, f.Attacks, r.Total.Attacks = k.Attacks+1, f.Attacks+1, r.Total.Attacks+1
			if o.Hit {
				k.Detected, f.Detected, r.Total.Detected = k.Detected+1, f.Detected+1, r.Total.Detected+1
			} else {
				r.Missed = append(r.Missed, c.ID)
			}
		} else {
			o.Hit = significant(fs)
			k.Benign, f.Benign, r.Total.Benign = k.Benign+1, f.Benign+1, r.Total.Benign+1
			if o.Hit {
				k.FalsePos, f.FalsePos, r.Total.FalsePos = k.FalsePos+1, f.FalsePos+1, r.Total.FalsePos+1
				r.FalsePos = append(r.FalsePos, c.ID)
			}
		}
		r.Outcomes = append(r.Outcomes, o)
	}
	return r
}

func (r *Report) stats(c Case) (*Stats, *Stats) {
	if r.ByKind[c.Kind] == nil {
		r.ByKind[c.Kind] = &Stats{}
	}
	if r.ByFamily[c.Label] == nil {
		r.ByFamily[c.Label] = &Stats{}
	}
	return r.ByKind[c.Kind], r.ByFamily[c.Label]
}

// Gates returns every failed gate (none: the corpus passes).
func (r Report) Gates() []string {
	var fails []string
	if v := r.Total.Recall(); v < GateRecall {
		fails = append(fails, fmt.Sprintf("recall %.3f < %.2f", v, GateRecall))
	}
	if v := r.Total.FPRate(); v > GateFPRate {
		fails = append(fails, fmt.Sprintf("false-positive rate %.3f > %.2f", v, GateFPRate))
	}
	if r.Total.Attacks < MinAttack || r.Total.Benign < MinBenign {
		fails = append(fails, fmt.Sprintf("corpus has %d attack and %d benign cases, need %d and %d", r.Total.Attacks, r.Total.Benign, MinAttack, MinBenign))
	}
	fromServers := 0
	for _, o := range r.Outcomes {
		if !o.Case.Attack() && o.Case.Source != "synthetic" {
			fromServers++
		}
	}
	if fromServers < MinBenign {
		fails = append(fails, fmt.Sprintf("only %d benign cases come from real servers, need %d", fromServers, MinBenign))
	}
	return fails
}

// MinCountsFile is the committed floor of cases per directory.
const MinCountsFile = "MIN_COUNTS"

// CheckMinCounts compares the corpus with <dir>/MIN_COUNTS ("<directory>
// <count>" per line, # comments): the corpus may grow, never shrink.
func CheckMinCounts(dir string, cases []Case) ([]string, error) {
	have := map[string]int{}
	for _, c := range cases {
		have[c.Dir]++
	}
	f, err := os.Open(filepath.Join(dir, MinCountsFile)) //nolint:gosec // G304: the corpus directory's own file
	if errors.Is(err, fs.ErrNotExist) {
		return []string{"missing " + MinCountsFile}, nil
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
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s: bad line %q", MinCountsFile, line)
		}
		n, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("%s: bad count in %q", MinCountsFile, line)
		}
		if have[parts[0]] < n {
			fails = append(fails, fmt.Sprintf("%s has %d cases, %s says at least %d", parts[0], have[parts[0]], MinCountsFile, n))
		}
	}
	return fails, sc.Err()
}

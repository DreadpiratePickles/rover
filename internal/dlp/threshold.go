package dlp

import (
	"math"
	"sync"
)

// The entropy threshold depends on the alphabet and the length. A random
// string of n bytes drawn from k symbols does not reach log2(k): with few
// draws some symbols repeat and others never appear. Its expected entropy
// is E(k, n) = log2(n) − (k/n)·E[c·log2 c], where c ~ Binomial(n, 1/k) is
// how often one symbol occurs. For 32 bytes that is about 4.27 for
// lowercase+digits (k = 36) and 4.56 for base64 (k = 64); for 256 bytes
// 5.07 and 5.81. A run is flagged when its entropy is at least E(k, n)
// minus entropyMargin (about 2.5 standard deviations at 32 bytes, more at
// longer lengths, where the spread shrinks): random tokens of any
// alphabet pass, identifiers and prose of the same alphabet do not.
const entropyMargin = 0.35

// alphabet is the symbol count of a run: digits, plus each letter case
// present, plus two symbols (+/ or -_) when any appears.
func alphabet(lower, upper, symbols bool) int {
	k := 10
	if lower {
		k += 26
	}
	if upper {
		k += 26
	}
	if symbols {
		k += 2
	}
	return k
}

var (
	thresholdsOnce sync.Once
	thresholds     map[int][]float64 // alphabet -> run length -> threshold
)

// threshold is the minimum entropy for a run of n bytes over k symbols.
func threshold(k, n int) float64 {
	thresholdsOnce.Do(func() {
		thresholds = map[int][]float64{}
		for _, k := range []int{12, 36, 38, 62, 64} {
			t := make([]float64, maxRun+1)
			for l := minRun; l <= maxRun; l++ {
				t[l] = expectedEntropy(k, l) - entropyMargin
			}
			thresholds[k] = t
		}
	})
	if t, ok := thresholds[k]; ok && n >= minRun && n <= maxRun {
		return t[n]
	}
	return expectedEntropy(k, n) - entropyMargin
}

// expectedEntropy is E(k, n), summing the binomial terms that matter.
func expectedEntropy(k, n int) float64 {
	p := 1 / float64(k)
	logP := float64(n) * math.Log1p(-p) // log P(c = 0)
	mean := float64(n) * p
	sum := 0.0
	for c := 1; c <= n; c++ {
		logP += math.Log(float64(n-c+1)/float64(c)) + math.Log(p/(1-p))
		prob := math.Exp(logP)
		sum += prob * float64(c) * math.Log2(float64(c))
		if float64(c) > mean && prob < 1e-12 {
			break
		}
	}
	return math.Log2(float64(n)) - float64(k)*sum/float64(n)
}

package pin

import (
	"errors"
	"fmt"
	"strings"
)

// Approve errors.
var (
	// ErrNothingToApprove: the tool is not blocked.
	ErrNothingToApprove = errors.New("nothing to approve")
	// ErrChangedSinceListed: the latest digest is not the one the human saw.
	ErrChangedSinceListed = errors.New("the tool changed again since you looked; run rover pin list")
	// ErrBadDigestPrefix: the prefix is not at least MinApprovePrefix hex digits.
	ErrBadDigestPrefix = fmt.Errorf("the digest prefix must be %d to 64 lowercase hex digits, as `rover pin list` prints it", MinApprovePrefix)
)

// MinApprovePrefix is the shortest digest prefix Approve accepts.
const MinApprovePrefix = 12

// ValidDigestPrefix reports whether s can name a digest for Approve.
func ValidDigestPrefix(s string) bool {
	if len(s) < MinApprovePrefix || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// Approve re-pins a mismatched tool to the definition the server sent most
// recently, but only if that definition's digest starts with digestPrefix:
// the human approves what they saw in `rover pin list`, and a server that
// changed again in between gets ErrChangedSinceListed (review M2). It
// returns the new pin and the digest approved before ("" if none).
// method is how the human proved they were there (M9: the OS dialog's
// method); roverd only calls Approve after that dialog succeeded.
func (c *Checker) Approve(server, tool, digestPrefix, method string) (Pinned, Digest, error) {
	if !ValidDigestPrefix(digestPrefix) {
		return Pinned{}, "", ErrBadDigestPrefix
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pins, err := c.load(server)
	if err != nil {
		return Pinned{}, "", err
	}
	p, err := approvable(pins, server, tool, digestPrefix)
	if err != nil {
		return Pinned{}, "", err
	}
	np := Pinned{Server: server, Tool: tool, Digest: p.Latest, ApprovedAt: c.now().UTC(), Method: method, Canonical: p.LatestCanonical}
	if err := c.store.Put(np); err != nil {
		return Pinned{}, "", err
	}
	pins[tool] = np
	return np, p.Digest, nil
}

// CheckApprovable reports the error Approve would return now, without
// changing anything. roverd calls it before showing the OS dialog, so the
// human is never asked to approve something that cannot be approved.
func (c *Checker) CheckApprovable(server, tool, digestPrefix string) error {
	if !ValidDigestPrefix(digestPrefix) {
		return ErrBadDigestPrefix
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pins, err := c.load(server)
	if err != nil {
		return err
	}
	_, err = approvable(pins, server, tool, digestPrefix)
	return err
}

func approvable(pins map[string]Pinned, server, tool, digestPrefix string) (Pinned, error) {
	p, known := pins[tool]
	switch {
	case !known:
		return Pinned{}, fmt.Errorf("%w: %s/%s has never been listed", ErrNothingToApprove, server, tool)
	case !p.Mismatch:
		return Pinned{}, fmt.Errorf("%w: %s/%s matches its pin", ErrNothingToApprove, server, tool)
	case p.Latest == "":
		return Pinned{}, fmt.Errorf("%s/%s cannot be approved: its definition has no canonical form (%s)", server, tool, p.Problem)
	case !strings.HasPrefix(string(p.Latest), digestPrefix):
		return Pinned{}, fmt.Errorf("%w (latest is %s, you approved %s)", ErrChangedSinceListed, p.Latest.Short(), digestPrefix)
	}
	return p, nil
}

// Reset forgets every pin of server; its next tools/list is trusted on
// first use again. roverd only calls it after the OS dialog succeeded (M9).
func (c *Checker) Reset(server string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.store.DeleteServer(server)
	delete(c.cache, server) // reload from the store either way
	delete(c.tofu, server)
	return n, err
}

// List returns the stored pins of server ("" for all), read fresh.
func (c *Checker) List(server string) ([]Pinned, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.List(server)
}

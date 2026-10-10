// Package keychain stores Rover's secrets (bridge tokens, M11) in the
// operating system's keychain and nowhere else (plan D10).
//
// LESSON (M11): a token in a file is a token any process running as you can
// read, back up to the cloud, or paste into a bug report. The OS keychain
// (macOS Keychain, the Secret Service on Linux) keeps it encrypted at rest
// and, on macOS, tied to the user's login. When no keychain exists (a
// headless Linux box with no Secret Service), Rover refuses instead of
// quietly writing a file: an error you can see beats a leak you cannot.
package keychain

import (
	"errors"
	"fmt"
	"sync"
)

// Service is the keychain service every Rover secret is stored under.
const Service = "rover"

// ErrNoKeychain means the platform has no usable keychain. There is no file
// fallback, by design.
var ErrNoKeychain = errors.New("no keychain available; Rover will not store tokens in a file")

// ErrNotFound means nothing is stored under that service and account.
var ErrNotFound = errors.New("no such keychain item")

// ErrTooBig means one item does not fit the platform's limit (macOS: about
// 4 KiB for service, account and secret together through /usr/bin/security).
var ErrTooBig = errors.New("keychain: the secret is too large for one keychain item")

// Keyring is the small part of a keychain Rover needs.
type Keyring interface {
	Get(service, account string) (string, error)
	Set(service, account, secret string) error
	Delete(service, account string) error
}

// Memory is an in-memory Keyring for tests. It never touches the disk.
type Memory struct {
	// Limit, if set, is the largest secret one item holds (ErrTooBig
	// above it), to play the macOS keychain.
	Limit int

	mu    sync.Mutex
	items map[string]string
}

// NewMemory returns an empty in-memory keyring.
func NewMemory() *Memory { return &Memory{items: map[string]string{}} }

func memKey(service, account string) string { return service + "\x00" + account }

// Get implements Keyring.
func (m *Memory) Get(service, account string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[memKey(service, account)]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Set implements Keyring.
func (m *Memory) Set(service, account, secret string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Limit > 0 && len(secret) > m.Limit {
		return fmt.Errorf("%w (%d bytes, limit %d)", ErrTooBig, len(secret), m.Limit)
	}
	m.items[memKey(service, account)] = secret
	return nil
}

// Delete implements Keyring.
func (m *Memory) Delete(service, account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey(service, account)
	if _, ok := m.items[k]; !ok {
		return ErrNotFound
	}
	delete(m.items, k)
	return nil
}

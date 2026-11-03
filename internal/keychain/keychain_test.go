package keychain

import (
	"errors"
	"strings"
	"testing"
)

func TestMemory(t *testing.T) {
	m := NewMemory()
	if _, err := m.Get(Service, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty get: %v", err)
	}
	if err := m.Set(Service, "a", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if v, err := m.Get(Service, "a"); err != nil || v != "s3cret" {
		t.Fatalf("get = %q, %v", v, err)
	}
	if _, err := m.Get("other", "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("service must separate items: %v", err)
	}
	if err := m.Delete(Service, "a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(Service, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
}

// Plan §8 fallback: no keychain means a clear refusal, never a file.
func TestNoKeychainRefuses(t *testing.T) {
	o := &OS{probe: func() error { return errors.New("dbus: couldn't determine address of session bus") }}
	if _, err := o.Get(Service, "x"); !errors.Is(err, ErrNoKeychain) {
		t.Fatalf("get: %v", err)
	}
	err := o.Set(Service, "x", "tok")
	if !errors.Is(err, ErrNoKeychain) {
		t.Fatalf("set: %v", err)
	}
	if want := "no keychain available; Rover will not store tokens in a file"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("message %q lacks %q", err, want)
	}
	if err := o.Delete(Service, "x"); !errors.Is(err, ErrNoKeychain) {
		t.Fatalf("delete: %v", err)
	}
}

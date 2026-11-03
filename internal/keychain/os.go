package keychain

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

// OS is the operating system's keychain through github.com/zalando/go-keyring
// (macOS: /usr/bin/security with the secret on its stdin; Linux: the Secret
// Service over D-Bus). Every call first checks that a keychain is there
// (probe, per platform) so a headless Linux box fails with ErrNoKeychain
// instead of auto-launching a D-Bus session that has no Secret Service.
type OS struct {
	// probe reports ErrNoKeychain when there is no keychain; tests replace it.
	probe func() error
}

// NewOS returns the OS keychain.
func NewOS() *OS { return &OS{probe: available} }

func (o *OS) check() error {
	if o.probe == nil {
		return nil
	}
	if err := o.probe(); err != nil {
		return fmt.Errorf("%w (%v)", ErrNoKeychain, err)
	}
	return nil
}

// Get implements Keyring.
func (o *OS) Get(service, account string) (string, error) {
	if err := o.check(); err != nil {
		return "", err
	}
	v, err := keyring.Get(service, account)
	return v, mapErr(err)
}

// Set implements Keyring.
func (o *OS) Set(service, account, secret string) error {
	if err := o.check(); err != nil {
		return err
	}
	return mapErr(keyring.Set(service, account, secret))
}

// Delete implements Keyring.
func (o *OS) Delete(service, account string) error {
	if err := o.check(); err != nil {
		return err
	}
	return mapErr(keyring.Delete(service, account))
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keyring.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, keyring.ErrUnsupportedPlatform):
		return fmt.Errorf("%w (%v)", ErrNoKeychain, err)
	case errors.Is(err, keyring.ErrSetDataTooBig):
		return fmt.Errorf("%w (%v)", ErrTooBig, err)
	}
	if noService(err) {
		return fmt.Errorf("%w (%v)", ErrNoKeychain, err)
	}
	return fmt.Errorf("keychain: %w", err)
}

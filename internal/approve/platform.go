package approve

import (
	"context"
	"fmt"
)

// Deny is the Authenticator of a platform with no OS dialog: it always
// denies, so an approval-required call is refused, never waved through.
type Deny struct{ Why string }

// Authenticate implements Authenticator.
func (d Deny) Authenticate(context.Context, string) (bool, string, error) {
	return false, "none", fmt.Errorf("%w: %s", ErrUnsupported, d.Why)
}

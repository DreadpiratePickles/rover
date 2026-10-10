//go:build darwin && cgo

package approve

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework LocalAuthentication
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdio.h>
#include <stdlib.h>

static void *rover_la_new(void) {
	LAContext *c = [[LAContext alloc] init];
	return (__bridge_retained void *)c;
}

static void rover_la_free(void *p) {
	LAContext *c = (__bridge_transfer LAContext *)p;
	c = nil;
}

static void rover_la_invalidate(void *p) {
	[(__bridge LAContext *)p invalidate];
}

// rover_la_eval shows the dialog and blocks until it is answered. The
// reply block runs on a LocalAuthentication queue, so waiting here on a
// semaphore is safe on any thread. Returns 1 on success; otherwise *code
// is the LAError code and msg its description.
static int rover_la_eval(void *p, const char *reason, long *code, char *msg, int msglen) {
	@autoreleasepool {
		LAContext *c = (__bridge LAContext *)p;
		NSString *r = [NSString stringWithUTF8String:reason];
		msg[0] = 0;
		if (r == nil) {
			*code = -100000;
			snprintf(msg, msglen, "reason is not UTF-8");
			return 0;
		}
		NSError *cerr = nil;
		if (![c canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&cerr]) {
			*code = cerr ? (long)cerr.code : -100001;
			snprintf(msg, msglen, "%s", cerr ? cerr.localizedDescription.UTF8String : "cannot evaluate the policy");
			return 0;
		}
		dispatch_semaphore_t sem = dispatch_semaphore_create(0);
		__block BOOL ok = NO;
		__block NSInteger ecode = 0;
		__block NSString *emsg = nil;
		[c evaluatePolicy:LAPolicyDeviceOwnerAuthentication
		  localizedReason:r
		            reply:^(BOOL success, NSError *error) {
			ok = success;
			if (error != nil) {
				ecode = error.code;
				emsg = [error.localizedDescription copy];
			}
			dispatch_semaphore_signal(sem);
		}];
		dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
		*code = (long)ecode;
		if (emsg != nil) {
			snprintf(msg, msglen, "%s", emsg.UTF8String);
		}
		return ok ? 1 : 0;
	}
}
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

// MethodLocalAuth is the method recorded for a macOS approval. The API
// does not say whether Touch ID, the password or a paired Apple Watch was
// used; all three prove the device owner is present (D9).
const MethodLocalAuth = "macos_local_authentication"

// LocalAuthentication error codes (LAError.h) Rover tells apart.
const (
	LAErrorAuthenticationFailed = -1
	LAErrorUserCancel           = -2
	LAErrorSystemCancel         = -4
	LAErrorPasscodeNotSet       = -5
	LAErrorAppCancel            = -9
	LAErrorNotInteractive       = -1004
)

// LAError is a LocalAuthentication failure.
type LAError struct {
	Code int
	Msg  string
}

func (e *LAError) Error() string {
	return fmt.Sprintf("LocalAuthentication error %d: %s", e.Code, e.Msg)
}

// LocalAuth shows the macOS authentication dialog with
// LAPolicyDeviceOwnerAuthentication: Touch ID (or a paired Watch) first,
// with "Use Password..." always available. 🔍 There is no password-only
// LAPolicy in the SDK (LAPublicDefines.h lists biometrics, device owner,
// companion/watch, biometrics-or-companion, wrist detection), so the plan's
// fallback applies: Touch ID or password are both accepted, and there is no
// auth.require_password setting.
type LocalAuth struct{}

// Platform returns this platform's Authenticator: LocalAuthentication.
func Platform(func(string, ...any)) Authenticator { return LocalAuth{} }

type laResult struct {
	ok   bool
	code int
	msg  string
}

// Authenticate implements Authenticator. A cancelled ctx closes the dialog.
// The user pressing Cancel is (false, nil); every other failure is an
// *LAError.
func (LocalAuth) Authenticate(ctx context.Context, reason string) (bool, string, error) {
	la := C.rover_la_new()
	creason := C.CString(reason)
	done := make(chan laResult, 1)
	go func() {
		var code C.long
		buf := make([]byte, 512)
		ok := C.rover_la_eval(la, creason, &code, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
		done <- laResult{ok: ok == 1, code: int(code), msg: C.GoString((*C.char)(unsafe.Pointer(&buf[0])))}
	}()
	var r laResult
	select {
	case r = <-done:
	case <-ctx.Done():
		C.rover_la_invalidate(la)
		r = <-done
	}
	C.rover_la_free(la)
	C.free(unsafe.Pointer(creason))
	switch {
	case r.ok:
		return true, MethodLocalAuth, nil
	case ctx.Err() != nil:
		return false, MethodLocalAuth, ctx.Err()
	case r.code == LAErrorUserCancel:
		return false, MethodLocalAuth, nil
	}
	if r.code == LAErrorNotInteractive {
		return false, MethodLocalAuth, fmt.Errorf("%w: %w", ErrNotInteractive, &LAError{Code: r.code, Msg: r.msg})
	}
	return false, MethodLocalAuth, &LAError{Code: r.code, Msg: r.msg}
}

// PlatformLimit says why approvals can never succeed in this build, or "".
func PlatformLimit() string { return "" }

package yaml2cedar

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

// FuzzCompile checks that Compile never panics, that every error is a
// *CompileError, and that whatever it does accept is Cedar that policy.Load
// accepts: the compiler must never emit text the engine refuses.
func FuzzCompile(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	for _, s := range seeds {
		if b, err := os.ReadFile(s); err == nil { //nolint:gosec // G304: test data
			f.Add(b)
		}
	}
	f.Add([]byte(head + "rules:\n  - id: 'x\") ; permit(principal, action, resource); //'\n    allow: a.b\n"))
	f.Add([]byte(head + "rules:\n  - id: a\n    alow: a.b\n"))
	f.Fuzz(func(t *testing.T, src []byte) {
		c, err := Compile(src, "fuzz.yaml")
		if err != nil {
			var ce *CompileError
			if !errors.As(err, &ce) {
				t.Fatalf("error is not a *CompileError: %v", err)
			}
			return
		}
		schema, err := policy.SchemaFor(policyfiles.Schema, policy.NewSchemaExtension(c.RootOrder, normalize.BuiltIn()))
		if err != nil {
			t.Fatalf("SchemaFor: %v", err)
		}
		if _, err := policy.Load(c.Cedar, "fuzz.cedar", schema); err != nil {
			t.Fatalf("compiled Cedar does not load: %v\n%s", err, c.Cedar)
		}
	})
}

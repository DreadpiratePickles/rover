package policy

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

const underLab = `@id("lab") permit (principal, action == Action::"call_tool", resource)
when { context.norm has path.under_lab && context.norm.path.under_lab };`

func TestSchemaForAddsConfiguredRoots(t *testing.T) {
	// Arrange
	withLab := NewSchemaExtension([]string{"lab"}, normalize.BuiltIn())
	withoutLab := NewSchemaExtension([]string{"projects"}, normalize.BuiltIn())

	// Act
	labSchema, err1 := SchemaFor(policyfiles.Schema, withLab)
	otherSchema, err2 := SchemaFor(policyfiles.Schema, withoutLab)

	// Assert
	if err1 != nil || err2 != nil {
		t.Fatalf("SchemaFor: %v / %v", err1, err2)
	}
	if _, err := Load([]byte(underLab), "lab.cedar", labSchema); err != nil {
		t.Errorf("with root lab: %v", err)
	}
	_, err := Load([]byte(underLab), "lab.cedar", otherSchema)
	if !errors.Is(err, ErrLoad) || !strings.Contains(err.Error(), "under_lab") {
		t.Errorf("without root lab: want an error naming under_lab, got %v", err)
	}
}

func TestShippedSchemaIsTheDefaultExtension(t *testing.T) {
	// Act
	got, err := SchemaFor(policyfiles.Schema, DefaultSchemaExtension())

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, policyfiles.Schema) {
		t.Errorf("policy/schema.cedarschema is not SchemaFor(itself, DefaultSchemaExtension()); regenerate it:\n%s", got)
	}
}

func TestSchemaForMakesEveryGeneratedAttributeOptional(t *testing.T) {
	// Act
	got, err := SchemaFor(policyfiles.Schema, NewSchemaExtension([]string{"a", "b"}, normalize.BuiltIn()))

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range generatedTypes {
		m := typeDeclRE.FindAllSubmatch(got, -1)
		for _, d := range m {
			if string(d[1]) != name {
				continue
			}
			body := string(d[0])
			if n := strings.Count(body, ":"); n != strings.Count(body, "?:") {
				t.Errorf("type %s has a required attribute:\n%s", name, body)
			}
		}
	}
	for _, want := range []string{"under_a?: Bool", "under_b?: Bool", "all_under_a?: Bool", "repo_path?: NormPath", "files?: NormPaths", "url?: NormURL"} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("generated schema lacks %q", want)
		}
	}
}

func TestSchemaForRejects(t *testing.T) {
	cases := map[string]struct {
		base []byte
		ext  SchemaExtension
	}{
		"root not an identifier":   {policyfiles.Schema, SchemaExtension{Roots: []string{"my-root"}}},
		"root is reserved":         {policyfiles.Schema, SchemaExtension{Roots: []string{"in"}}},
		"arg with two kinds":       {policyfiles.Schema, SchemaExtension{NormPathArgs: []string{"x"}, NormURLArgs: []string{"x"}}},
		"arg not an identifier":    {policyfiles.Schema, SchemaExtension{ArgNames: []string{"a b"}}},
		"base without Norm":        {[]byte(`type Args = {};`), SchemaExtension{}},
		"base declares Args twice": {append(append([]byte(nil), policyfiles.Schema...), "\ntype Args = {};\n"...), SchemaExtension{}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			_, err := SchemaFor(c.base, c.ext)

			// Assert
			if !errors.Is(err, ErrLoad) {
				t.Fatalf("want ErrLoad, got %v", err)
			}
		})
	}
}

func TestSchemaForIsDeterministic(t *testing.T) {
	// Arrange
	ext := NewSchemaExtension([]string{"z", "a"}, normalize.BuiltIn())

	// Act
	a, _ := SchemaFor(policyfiles.Schema, ext)
	b, _ := SchemaFor(policyfiles.Schema, ext)

	// Assert
	if !bytes.Equal(a, b) {
		t.Fatal("two calls with the same extension differ")
	}
}

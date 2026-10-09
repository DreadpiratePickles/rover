// Package policyfiles embeds the Cedar files Rover ships: the schema (plan
// §5.1), the starter policy written by `rover policy init`, and the policy
// templates. The files live next to this one so they can be read and edited
// as plain Cedar; the Go package only makes them available to the binary.
package policyfiles

import (
	"embed"
	"io/fs"
)

// Schema is the rover-gate Cedar schema (plan §5.1) every policy is
// validated against.
//
//go:embed schema.cedarschema
var Schema []byte

// Starter is the policy `rover policy init` writes: it denies sampling and
// elicitation and permits nothing else.
//
//go:embed starter.cedar
var Starter []byte

//go:embed templates/*.cedar
var templates embed.FS

// Templates holds the policy templates, named "<template>.cedar" at the root
// of the file system (for example "deny-sampling.cedar").
var Templates fs.FS = mustSub(templates, "templates")

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		// fs.Sub only fails for an invalid path, and "templates" is a constant.
		panic(err)
	}
	return sub
}

package main

import (
	"bytes"
	"strings"
	"testing"
)

// LOW-2 (review): a name that only matched a built-in after removing a
// packaging prefix or suffix (typically `rover wrap` without --name, whose
// name is the command's base name) gets a warning line.
func TestPrintLabelsWarnsOnTrimmedMatch(t *testing.T) {
	// Arrange
	var out bytes.Buffer

	// Act
	printLabels(&out, []string{"git", "mcp-server-git"}, nil)

	// Assert
	got := out.String()
	if !strings.Contains(got, "warning: mcp-server-git matched the built-in git labels only by its name") {
		t.Fatalf("no warning for the trimmed match:\n%s", got)
	}
	if strings.Contains(got, "warning: git ") {
		t.Fatalf("an exact name must not warn:\n%s", got)
	}
}

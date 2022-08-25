package util

import (
	"bytes"
	"go/format"
	"go/token"
)

// String returns string format of a node
func String(n any) string {
	fset := token.NewFileSet()
	return formatNode(fset, n)
}

func formatNode(fset *token.FileSet, n any) string {
	var buf bytes.Buffer
	format.Node(&buf, fset, n)
	// Indent secondary lines by a tab.
	return string(bytes.Replace(buf.Bytes(), []byte("\n"), []byte("\n\t"), -1))
}

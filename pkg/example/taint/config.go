package taint

import (
	"github.com/cokeBeer/goot/pkg/example/taint/rule"
	"golang.org/x/tools/go/ssa"
)

// TaintConfig represents a configuration for taint analysis
type TaintConfig struct {
	PassThroughContainer *map[string][][]int
	InitMap              *map[string]*ssa.Function
	History              *map[string]bool
	InterfaceHierarchy   *InterfaceHierarchy
	CallGraph            *CallGraph
	Ruler                rule.Ruler
	PassThroughOnly      bool
	Debug                bool
}

// PrintBody represents the name of the function should be printed
const PrintBody = ""

// Store represents the path of the passthrough data
const Store = "gostd.json"

// Gostd reprents all go standard library's PkgPath
var Gostd = []string{"archive...", "bufio...", "builtin...", "bytes...",
	"compress...", "container...", "context...", "crypto...",
	"database...", "debug...", "embed...", "encoding...", "errors...", "expvar...",
	"flag...", "fmt...", "go...", "hash...", "html...",
	"image...", "index...", "io...", "log...", "math...", "mime...",
	"net...", "os...", "path...", "plugin...", "relect...", "regexp...", "runtime...",
	"sort...", "strconv...", "strings...", "sync...", "syscall...",
	"text...", "time...", "unicode...", "unsafe..."}

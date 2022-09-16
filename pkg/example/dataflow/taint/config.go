package taint

import (
	"github.com/cokeBeer/goot/pkg/example/dataflow/taint/rule"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// TaintConfig represents a configuration for taint analysis
type TaintConfig struct {
	PassThroughContainer *map[string][][]int
	InitMap              *map[string]*ssa.Function
	History              *map[string]bool
	InterfaceHierarchy   *InterfaceHierarchy
	TaintGraph           *TaintGraph
	CallGraph            *callgraph.Graph
	Ruler                rule.Ruler
	PassThroughOnly      bool
	TargetFunc           string
	Debug                bool
	PassBack             bool
}

// Gostd reprents all go standard library's PkgPath
var Gostd = []string{"archive...", "bufio...", "builtin...", "bytes...",
	"compress...", "container...", "context...", "crypto...",
	"database...", "debug...", "embed...", "encoding...", "errors...", "expvar...",
	"flag...", "fmt...", "go...", "hash...", "html...",
	"image...", "index...", "io...", "log...", "math...", "mime...",
	"net...", "os...", "path...", "plugin...", "relect...", "regexp...", "runtime...",
	"sort...", "strconv...", "strings...", "sync...", "syscall...",
	"text...", "time...", "unicode...", "unsafe..."}

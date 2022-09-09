package constantpropagation

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"log"

	"github.com/cokeBeer/goot/pkg/dataflow/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/dataflow/toolkits/solver"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Runner represents a constant propagation runner
type Runner struct {
	Src      string
	Function string
}

// Run kick off the analysis
func (r *Runner) Run() {
	// Generate ast
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", r.Src, parser.Mode(0))
	if err != nil {
		log.Println(err)
	}
	files := []*ast.File{f}

	// Build package
	pkg := types.NewPackage("constantpropagtionanalysis", "")
	hello, _, err := ssautil.BuildPackage(
		&types.Config{Importer: importer.Default()}, fset, pkg, files, ssa.SanityCheckFunctions)
	if err != nil {
		log.Println(err)
	}

	// Build graph
	graph := graph.New(hello.Func(r.Function))

	// Build analysis
	analysis := New(graph)

	// Solve analysis
	solver.Solve(analysis, true)
}

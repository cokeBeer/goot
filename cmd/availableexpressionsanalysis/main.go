package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log"

	"github.com/cokeBeer/goot/pkg/example/availableexpressionsanalysis/analysis"
	"github.com/cokeBeer/goot/pkg/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/toolkits/solver"
)

const src = `package main

func main(a int, b int, x int, y int) int {
	x = a + b
	y = a * b
	for y > a {
		a = a + 1
		x = a + b
	}
	return x
}`

func main() {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.Mode(0))
	if err != nil {
		log.Println(err)
	}
	for _, decl := range f.Decls {
		if decl, ok := decl.(*ast.FuncDecl); ok {
			nodeGraph := graph.New(decl)
			flowAnalysis := analysis.New(nodeGraph)
			solver.Solve(flowAnalysis)
		}
	}
}

package main

import (
	"log"

	"github.com/cokeBeer/goot/pkg/pta/cs"
	"github.com/cokeBeer/goot/pkg/pta/heap"
	"github.com/cokeBeer/goot/pkg/pta/solver"
	"github.com/cokeBeer/goot/pkg/pta/world"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa/ssautil"
)

func main() {
	mode := packages.NeedName |
		packages.NeedFiles |
		packages.NeedCompiledGoFiles |
		packages.NeedSyntax |
		packages.NeedTypesInfo |
		packages.NeedImports |
		packages.NeedTypesSizes |
		packages.NeedTypes |
		packages.NeedDeps
	cfg := &packages.Config{Mode: mode}
	mainFunction := "github.com/cokeBeer/goot/pkg/bench/pta.main"
	initial, err := packages.Load(cfg, "../../pkg/bench/pta")
	if err != nil {
		log.Fatal(err)
	}
	prog, _ := ssautil.AllPackages(initial, 0)
	prog.Build()
	funcs := ssautil.AllFunctions(prog)
	world.WorldInstance.BuildWorld(&funcs, mainFunction)
	solver.NewSolver(heap.NewHeapModel(), cs.NewContextSelector(), cs.NewContextSensitiveManager())
}

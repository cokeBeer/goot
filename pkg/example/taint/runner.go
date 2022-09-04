package taint

import (
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Runner represents a analysis runner
type Runner struct {
	PkgPath []string
	Debug   bool
	SrcPath string
	DstPath string
}

// NewRunner returns a *taint.Runner
func NewRunner(PkgPath ...string) *Runner {
	return &Runner{PkgPath: PkgPath, SrcPath: "", DstPath: "", Debug: false}
}

// Run kick off an analysis
func (r *Runner) Run() error {
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
	initial, err := packages.Load(cfg, r.PkgPath...)
	if err != nil {
		return err
	}

	prog, _ := ssautil.AllPackages(initial, 0)
	prog.Build()

	funcs := ssautil.AllFunctions(prog)

	interfaceHierarchy := Build(&funcs)

	passThroughContainter := make(map[string][][]int)
	if r.SrcPath != "" {
		Fetch(&passThroughContainter, r.SrcPath)
	}

	initMap := make(map[string]*ssa.Function)
	history := make(map[string]bool)

	c := &TaintConfig{PassThroughContainer: &passThroughContainter,
		InitMap:            &initMap,
		History:            &history,
		InterfaceHierarchy: interfaceHierarchy,
		Debug:              r.Debug}

	for f := range funcs {
		if f.Name() == "init" {
			Run(f, c)
		}
	}

	for f := range funcs {
		if f.String() != "init" {
			Run(f, c)
		}
	}

	if r.DstPath != "" {
		Persist(&passThroughContainter, r.DstPath)
	}

	return nil
}

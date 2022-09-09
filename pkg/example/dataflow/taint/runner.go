package taint

import (
	"github.com/cokeBeer/goot/pkg/example/dataflow/taint/rule"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Runner represents a analysis runner
type Runner struct {
	ModuleName         string
	PkgPath            []string
	Debug              bool
	InitOnly           bool
	PassThroughOnly    bool
	PassThroughSrcPath string
	PassThroughDstPath string
	CallGraphDstPath   string
	Ruler              rule.Ruler
}

// NewRunner returns a *taint.Runner
func NewRunner(PkgPath ...string) *Runner {
	return &Runner{PkgPath: PkgPath, ModuleName: "",
		PassThroughSrcPath: "", PassThroughDstPath: "",
		CallGraphDstPath: "", Ruler: nil,
		Debug: false, InitOnly: false, PassThroughOnly: false}
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

	interfaceHierarchy := NewInterfaceHierarchy(&funcs)
	var ruler rule.Ruler
	if r.Ruler != nil {
		ruler = r.Ruler
	} else {
		ruler = &DummyRuler{*rule.New(r.ModuleName)}
	}
	callGraph := NewCallGraph(&funcs, ruler)

	passThroughContainter := make(map[string][][]int)
	if r.PassThroughSrcPath != "" {
		FetchPassThrough(&passThroughContainter, r.PassThroughSrcPath)
	}

	initMap := make(map[string]*ssa.Function)
	history := make(map[string]bool)

	c := &TaintConfig{PassThroughContainer: &passThroughContainter,
		InitMap:            &initMap,
		History:            &history,
		InterfaceHierarchy: interfaceHierarchy,
		CallGraph:          callGraph,
		Ruler:              ruler,
		PassThroughOnly:    r.PassThroughOnly,
		Debug:              r.Debug}

	for f := range funcs {
		if f.Name() == "init" {
			Run(f, c)
		}
	}

	if !r.InitOnly {
		for f := range funcs {
			if f.String() != "init" {
				Run(f, c)
			}
		}
	}

	if r.PassThroughDstPath != "" {
		PersistPassThrough(&passThroughContainter, r.PassThroughDstPath)
	}
	if r.CallGraphDstPath != "" {
		PersistCallGraph(callGraph.Edges, r.CallGraphDstPath)
	}

	return nil
}

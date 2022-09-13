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
	PassThroughSrcPath []string
	PassThroughDstPath string
	CallGraphDstPath   string
	Ruler              rule.Ruler
	PersistToNeo4j     bool
	Neo4jUsername      string
	Neo4jPassword      string
	Neo4jURI           string
	TargetFunc         string
	PassBack           bool
}

// NewRunner returns a *taint.Runner
func NewRunner(PkgPath ...string) *Runner {
	return &Runner{PkgPath: PkgPath, ModuleName: "",
		PassThroughSrcPath: nil, PassThroughDstPath: "",
		CallGraphDstPath: "", Ruler: nil,
		Debug: false, InitOnly: false, PassThroughOnly: false,
		PersistToNeo4j: false, Neo4jURI: "", Neo4jUsername: "", Neo4jPassword: "",
		TargetFunc: "", PassBack: false}
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
		ruler = NewDummyRuler(r.ModuleName)
	}
	callGraph := NewCallGraph(&funcs, ruler)

	passThroughContainter := make(map[string][][]int)
	if r.PassThroughSrcPath != nil {
		FetchPassThrough(&passThroughContainter, r.PassThroughSrcPath)
	}

	passThroughContainter["github.com/cokeBeer/goot/pkg/bench/copy.Copy"] = [][]int{{0}, {0, 1}}

	initMap := make(map[string]*ssa.Function)
	history := make(map[string]bool)

	c := &TaintConfig{PassThroughContainer: &passThroughContainter,
		InitMap:            &initMap,
		History:            &history,
		InterfaceHierarchy: interfaceHierarchy,
		CallGraph:          callGraph,
		Ruler:              ruler,
		PassThroughOnly:    r.PassThroughOnly,
		Debug:              r.Debug,
		TargetFunc:         r.TargetFunc,
		PassBack:           r.PassBack}

	for f := range funcs {
		if f.Name() == "init" {
			Run(f, c)
		}
	}

	if !r.InitOnly {
		for f := range funcs {
			if f.String() != "init" {
				if r.TargetFunc != "" && f.String() != r.TargetFunc {
					continue
				}
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
	if !r.PassThroughOnly && r.PersistToNeo4j {
		PersistToNeo4j(callGraph.Nodes, callGraph.Edges, r.Neo4jURI, r.Neo4jUsername, r.Neo4jPassword)
	}
	return nil
}

package taint

import (
	"fmt"
	"go/types"
	"os"

	"github.com/cokeBeer/goot/pkg/dataflow/golang/switcher"
	"github.com/cokeBeer/goot/pkg/dataflow/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/dataflow/toolkits/scalar"
	"github.com/cokeBeer/goot/pkg/dataflow/toolkits/solver"
	"github.com/cokeBeer/goot/pkg/dataflow/util/entry"
	"github.com/cokeBeer/goot/pkg/example/dataflow/taint/rule"
	"golang.org/x/tools/go/ssa"
)

// TaintAnalysis represents a taint analysis
type TaintAnalysis struct {
	scalar.BaseFlowAnalysis
	taintSwitcher        *TaintSwitcher
	passThrough          []*TaintWrapper
	config               *TaintConfig
	passThroughContainer *map[string][][]int
	initMap              *map[string]*ssa.Function
	interfaceHierarchy   *InterfaceHierarchy
	callGraph            *CallGraph
	ruler                rule.Ruler
}

// Run kicks off a taint analysis on a function
func Run(f *ssa.Function, c *TaintConfig) {
	// if has recorded in passThroughContainer in somewhere else, skip
	if _, ok := (*c.PassThroughContainer)[f.String()]; ok {
		return
	}

	if needNull(f, c) {
		// if the function is in recursive or has no body, init as null
		initNull(f, c)
		return
	}

	if f.Name() == c.TargetFunc {
		f.WriteTo(os.Stdout)
	}

	// else, do run an analysis on a *ssa.Function
	doRun(f, c)
}

func doRun(f *ssa.Function, c *TaintConfig) {
	// mark function as visited in history to inhibit recursive
	pushHistory(f, c)

	// create a new analysis
	g := graph.New(f)
	a := New(g, c)

	// solve the analysis in debug mode
	solver.Solve(a, c.Debug)
}

func pushHistory(f *ssa.Function, c *TaintConfig) {
	(*c.History)[f.String()] = true
}

func initNull(f *ssa.Function, c *TaintConfig) {
	passThrough := make([][]int, 0)

	// the function has no body or in recursive
	// so init it by null passThrough
	if f.Signature.Recv() != nil {
		passThrough = append(passThrough, make([]int, 0))
	}

	n := f.Signature.Results().Len()
	for i := 0; i < n; i++ {
		passThrough = append(passThrough, make([]int, 0))
	}
	(*c.PassThroughContainer)[f.String()] = passThrough
	fmt.Println("finish analysis for:", f.String(), ", result: ", passThrough)
}

func needNull(f *ssa.Function, c *TaintConfig) bool {
	// is the function has no body?
	if f.Blocks == nil {
		return true
	}

	// is the function has marked as visited?
	if _, ok := (*c.History)[f.String()]; ok {
		return true
	}
	return false
}

// New creates a TaintAnalysis
func New(g *graph.UnitGraph, c *TaintConfig) *TaintAnalysis {
	taintAnalysis := new(TaintAnalysis)
	taintAnalysis.BaseFlowAnalysis = *scalar.NewBase(g)
	taintSwitcher := new(TaintSwitcher)
	taintSwitcher.taintAnalysis = taintAnalysis
	taintAnalysis.taintSwitcher = taintSwitcher
	taintAnalysis.config = c
	taintAnalysis.passThroughContainer = c.PassThroughContainer
	taintAnalysis.initMap = c.InitMap
	taintAnalysis.passThrough = make([]*TaintWrapper, 0)
	taintAnalysis.interfaceHierarchy = c.InterfaceHierarchy
	taintAnalysis.callGraph = c.CallGraph
	taintAnalysis.ruler = c.Ruler
	f := taintAnalysis.Graph.Func

	// init param taints in passThrough
	if f.Signature.Recv() != nil {
		// if the function has a receiver, add a position for receiver's taint
		recvMap := NewTaintWrapper(f.Params[0].Name())
		taintAnalysis.passThrough = append(taintAnalysis.passThrough, recvMap)
	}

	n := f.Signature.Results().Len()
	for i := 0; i < n; i++ {
		taintAnalysis.passThrough = append(taintAnalysis.passThrough, NewTaintWrapper())
	}

	n = f.Signature.Params().Len()
	for i := 0; i < n; i++ {
		taintAnalysis.passThrough = append(taintAnalysis.passThrough, NewTaintWrapper())
	}
	return taintAnalysis
}

// NewInitalFlow returns a new flow
func (a *TaintAnalysis) NewInitalFlow() *map[any]any {
	m := make(map[any]any)

	for _, v := range a.Graph.Func.Params {
		// init param taints in flow
		SetTaint(&m, v.Name(), v.Name())
	}
	return &m
}

// Computations limits number of computations on a flow graph
func (a *TaintAnalysis) Computations() int {
	return 3000
}

// FlowThrougth calculates outMap based on inMap and unit
func (a *TaintAnalysis) FlowThrougth(inMap *map[any]any, unit ssa.Instruction, outMap *map[any]any) {
	a.Copy(inMap, outMap)
	a.apply(inMap, unit, outMap)
}

// apply calls switcher.Apply
func (a *TaintAnalysis) apply(inMap *map[any]any, inst ssa.Instruction, outMap *map[any]any) {
	a.taintSwitcher.inMap = inMap
	a.taintSwitcher.outMap = outMap
	switcher.Apply(a.taintSwitcher, inst)
}

// MergeInto merges from in to inout based on unit
func (a *TaintAnalysis) MergeInto(unit ssa.Instruction, inout *map[any]any, in *map[any]any) {
	for name, wrapper := range *in {
		if _, ok := (*inout)[name]; ok {
			// if inout and in have a same key, merge the value first
			MergeTaintWrapper(inout, in, name.(string))
		} else {
			// else copy key and value from in to out directly
			SetTaintWrapper(inout, name.(string), wrapper.(*TaintWrapper))
		}
	}
}

// End handles result of analysis
func (a *TaintAnalysis) End(universe []*entry.Entry) {
	f := a.Graph.Func

	if f.Signature.Recv() != nil {
		// reset receiver's taint if it is a value receiver
		switch a.Graph.Func.Signature.Recv().Type().(type) {
		case *types.Named:
			recv := NewTaintWrapper(a.Graph.Func.Params[0].Name())
			a.passThrough[0] = recv
		}
	}

	passThrough := make([][]int, 0)
	params := f.Params
	n := len(params)
	for _, v := range a.passThrough {
		singlePassThrough := make([]int, 0)
		for i := 0; i < n; i++ {
			// for every return value, checks its taints from which param, and records
			if ok := v.HasTaint(params[i].Name()); ok {
				singlePassThrough = append(singlePassThrough, i)
			}
		}
		passThrough = append(passThrough, singlePassThrough)
	}
	// save passThrough to passThroughContainer
	(*a.passThroughContainer)[f.String()] = passThrough
	fmt.Println("end analysis for: "+f.String()+", result: ", passThrough)
}

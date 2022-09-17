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
	"golang.org/x/tools/go/ssa"
)

// TaintAnalysis represents a taint analysis
type TaintAnalysis struct {
	scalar.BaseFlowAnalysis
	taintSwitcher *TaintSwitcher
	passThrough   *PassThrough
	config        *TaintConfig
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

	if f.String() == c.TargetFunc {
		f.WriteTo(os.Stdout)
	}

	// else, do run an analysis on a *ssa.Function
	doRun(f, c)
}

func doRun(f *ssa.Function, c *TaintConfig) {
	// mark function as visited in history to inhibit recursive
	recordCall(f, c)

	// create a new analysis
	g := graph.New(f)
	a := New(g, c)

	// solve the analysis in debug mode
	solver.Solve(a, c.Debug)
}

func recordCall(f *ssa.Function, c *TaintConfig) {
	(*c.History)[f.String()] = true
	c.CallStack.PushBack(f)
}

func initNull(f *ssa.Function, c *TaintConfig) {

	// the function has no body or in recursive
	// so init it by null passThrough
	names := make([]string, 0)
	for _, param := range f.Params {
		names = append(names, param.Name())
	}
	recv := f.Signature.Recv() != nil
	result := f.Signature.Results().Len()
	param := f.Signature.Params().Len()
	passThrough := NewPassThrough(names, recv, result, param)
	passThroughCache := passThrough.ToCache()
	(*c.PassThroughContainer)[f.String()] = passThroughCache
	fmt.Println("end analysis for:", f.String(), ", result: ", passThroughCache)
}

func needNull(f *ssa.Function, c *TaintConfig) bool {
	// is the function has no body?
	if f.Blocks == nil {
		return true
	}

	// is the function has marked as visited?
	if _, ok := (*c.History)[f.String()]; ok {
		caller := c.CallStack.Back().Value.(*ssa.Function)
		IsCallerExported := false
		IsCalleeExported := true
		IsSamePackage := false
		if caller.Object() != nil && caller.Object().Exported() {
			IsCallerExported = true
		}
		if f.Object() != nil && !f.Object().Exported() {
			IsCalleeExported = false
		}
		if caller.Pkg != nil && f.Pkg != nil && caller.Pkg.String() == f.Pkg.String() {
			IsSamePackage = true
		}
		if IsCallerExported && !IsCalleeExported && IsSamePackage {
			return false
		}
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

	f := taintAnalysis.Graph.Func
	names := make([]string, 0)
	for _, v := range f.Params {
		names = append(names, v.Name())
	}

	recv := f.Signature.Recv() != nil
	result := f.Signature.Results().Len()
	param := f.Signature.Params().Len()

	taintAnalysis.passThrough = NewPassThrough(names, recv, result, param)
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
	c := a.config

	if f.Signature.Recv() != nil && false {
		// reset receiver's taint if it is a value receiver
		switch a.Graph.Func.Signature.Recv().Type().(type) {
		case *types.Named:
			recv := NewTaintWrapper(a.Graph.Func.Params[0].Name())
			a.passThrough.Recv = recv
		}
	}

	// save passThrough to passThroughContainer
	passThroughCache := a.passThrough.ToCache()
	(*c.PassThroughContainer)[f.String()] = passThroughCache

	// pop callStack
	c.CallStack.Remove(c.CallStack.Back())

	fmt.Println("finish analysis for: "+f.String()+", result: ", passThroughCache)
}

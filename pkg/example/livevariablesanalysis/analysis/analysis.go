package analysis

import (
	"fmt"
	"go/ast"

	"github.com/cokeBeer/goot/pkg/example/livevariablesanalysis/switcher"
	"github.com/cokeBeer/goot/pkg/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/toolkits/scalar"
	"github.com/cokeBeer/goot/pkg/util"
	"github.com/cokeBeer/goot/pkg/util/entry"
)

// LiveVariablesFlowAnalysis represents a live variables analysis
type LiveVariablesFlowAnalysis struct {
	scalar.BaseFlowAnalysis
}

// New returns a liveVaribalesFlowAnalysis
func New(g *graph.NodeGraph) *LiveVariablesFlowAnalysis {
	liveVariablesFlowAnalysis := new(LiveVariablesFlowAnalysis)
	liveVariablesFlowAnalysis.BaseFlowAnalysis = *scalar.NewBase(g)
	return liveVariablesFlowAnalysis
}

// GetGraph returns the Graph member in an LiveVariablesFlowAnalysis
func (a *LiveVariablesFlowAnalysis) GetGraph() *graph.NodeGraph {
	return a.Graph
}

// IsForward returns false because LiveVariables analysis is Backward
func (a *LiveVariablesFlowAnalysis) IsForward() bool {
	return false
}

// GetInitialMap returns the InitialMap member in a LiveVariablesFlowAnalysis
func (a *LiveVariablesFlowAnalysis) GetInitialMap() *map[any]any {
	return a.InitialMap
}

// FlowThrougth calculate outMap based on inMap and node
func (a *LiveVariablesFlowAnalysis) FlowThrougth(inMap *map[any]any, node ast.Node, outMap *map[any]any) {
	a.Copy(inMap, outMap)
	switcher := switcher.Apply(node)
	// Kill then Gen, which is the same as dataflow equation
	for _k := range *switcher.Kill {
		delete(*outMap, _k)
	}
	for _k := range *switcher.Gen {
		(*outMap)[_k] = true
	}
}

// NewInitalFlow returns a new flow
func (a *LiveVariablesFlowAnalysis) NewInitalFlow() *map[any]any {
	m := make(map[any]any)
	return &m
}

// EntryInitalFlow returns a new flow for entry
func (a *LiveVariablesFlowAnalysis) EntryInitalFlow() *map[any]any {
	return a.NewInitalFlow()
}

// Copy copy from srcMap to dstMap
func (a *LiveVariablesFlowAnalysis) Copy(srcMap *map[any]any, dstMap *map[any]any) {
	for k, v := range *srcMap {
		(*dstMap)[k] = v
	}
}

// MergeInto merge from in to inout based on node
func (a *LiveVariablesFlowAnalysis) MergeInto(node ast.Node, inout *map[any]any, in *map[any]any) {
	// Live Variables is a May problem, so take union
	for k, v := range *in {
		(*inout)[k] = v
	}
}

// End handle result of analysis
func (a *LiveVariablesFlowAnalysis) End(universe []*entry.Entry) {
	for _, v := range universe {
		fmt.Println("outFlow of node: " + util.String(v.Data))
		for n := range *v.OutFlow {
			fmt.Println(n)
		}
	}
}

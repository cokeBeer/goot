package scalar

import (
	"go/ast"

	"github.com/cokeBeer/goot/pkg/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/util/entry"
)

// BaseFlowAnalysis represents a base flow analysis implementation
type BaseFlowAnalysis struct {
	InitialMap *map[any]any
	Graph      *graph.NodeGraph
}

// NewBase returns a BaseFlowAnalysis
func NewBase(g *graph.NodeGraph) *BaseFlowAnalysis {
	BaseFlowAnalysis := new(BaseFlowAnalysis)
	BaseFlowAnalysis.Graph = g
	return BaseFlowAnalysis
}

// GetGraph returns the Graph memeber in a BaseFlowAnalysis
func (a *BaseFlowAnalysis) GetGraph() *graph.NodeGraph {
	return a.Graph
}

// IsForward returns whether this analysis is a forward flow analysis
func (a *BaseFlowAnalysis) IsForward() bool {
	return true
}

// GetInitialMap returns the InitialMap member in a BaseFlowAnalysis
func (a *BaseFlowAnalysis) GetInitialMap() *map[any]any {
	return a.InitialMap
}

// FlowThrougth calculate outMap based on inMap and node
func (a *BaseFlowAnalysis) FlowThrougth(inMap *map[any]any, node ast.Node, outMap *map[any]any) {
	a.Copy(inMap, outMap)
}

// NewInitalFlow returns a new flow
func (a *BaseFlowAnalysis) NewInitalFlow() *map[any]any {
	m := make(map[any]any)
	return &m
}

// EntryInitalFlow returns a new flow for entry
func (a *BaseFlowAnalysis) EntryInitalFlow() *map[any]any { return a.NewInitalFlow() }

// Copy copy from srcMap to dstMap
func (a *BaseFlowAnalysis) Copy(srcMap *map[any]any, dstMap *map[any]any) {
	for k, v := range *srcMap {
		(*dstMap)[k] = v
	}
}

// MergeInto merge from in to inout based on node
func (a *BaseFlowAnalysis) MergeInto(node ast.Node, inout *map[any]any, in *map[any]any) {
	for k, v := range *in {
		(*inout)[k] = v
	}
}

// End handle result of analysis
func (a *BaseFlowAnalysis) End(universe []*entry.Entry) {

}

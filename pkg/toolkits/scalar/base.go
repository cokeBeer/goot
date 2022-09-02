package scalar

import (
	"math"

	"github.com/cokeBeer/goot/pkg/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/util/entry"
	"golang.org/x/tools/go/ssa"
)

// BaseFlowAnalysis represents a base flow analysis implemention
type BaseFlowAnalysis struct {
	Graph *graph.UnitGraph
}

// NewBase returns a BaseFlowAnalysis
func NewBase(g *graph.UnitGraph) *BaseFlowAnalysis {
	BaseFlowAnalysis := new(BaseFlowAnalysis)
	BaseFlowAnalysis.Graph = g
	return BaseFlowAnalysis
}

// GetGraph returns the Graph memeber in a BaseFlowAnalysis
func (a *BaseFlowAnalysis) GetGraph() *graph.UnitGraph {
	return a.Graph
}

// IsForward returns whether this analysis is a forward flow analysis
func (a *BaseFlowAnalysis) IsForward() bool {
	return true
}

// Computations limit number of computations on a flow graph
func (a *BaseFlowAnalysis) Computations() int {
	return math.MaxInt
}

// FlowThrougth calculate outMap based on inMap and unit
func (a *BaseFlowAnalysis) FlowThrougth(inMap *map[any]any, unit ssa.Instruction, outMap *map[any]any) {
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

// MergeInto merge from in to inout based on unit
func (a *BaseFlowAnalysis) MergeInto(unit ssa.Instruction, inout *map[any]any, in *map[any]any) {
	for k, v := range *in {
		(*inout)[k] = v
	}
}

// End handle result of analysis
func (a *BaseFlowAnalysis) End(universe []*entry.Entry) {

}

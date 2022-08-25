package analysis

import (
	"fmt"
	"go/ast"

	"github.com/cokeBeer/goot/pkg/example/availableexpressionsanalysis/switcher"
	"github.com/cokeBeer/goot/pkg/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/toolkits/scalar"
	"github.com/cokeBeer/goot/pkg/util"
	"github.com/cokeBeer/goot/pkg/util/entry"
)

// AvailableExpressionsFlowAnalysis represents an available expressions analysis
type AvailableExpressionsFlowAnalysis struct {
	scalar.BaseFlowAnalysis
}

// New returns an AvalibaleExpressionsFlowAnalysis
func New(g *graph.NodeGraph) *AvailableExpressionsFlowAnalysis {
	availableExpressionsFlowAnalysis := new(AvailableExpressionsFlowAnalysis)
	availableExpressionsFlowAnalysis.BaseFlowAnalysis = *scalar.NewBase(g)
	return availableExpressionsFlowAnalysis
}

// GetGraph returns the Graph member in an availableExpressionsFlowAnalysis
func (a *AvailableExpressionsFlowAnalysis) GetGraph() *graph.NodeGraph {
	return a.Graph
}

// IsForward returns true because Available Expressions analysis is Forward
func (a *AvailableExpressionsFlowAnalysis) IsForward() bool {
	return true
}

// GetInitialMap returns the InitialMap member in an AvailableExpressionsAnalysis
func (a *AvailableExpressionsFlowAnalysis) GetInitialMap() *map[any]any {
	return a.InitialMap
}

// FlowThrougth calculate outMap based on inMap and node
func (a *AvailableExpressionsFlowAnalysis) FlowThrougth(inMap *map[any]any, node ast.Node, outMap *map[any]any) {
	a.Copy(inMap, outMap)
	switcher := switcher.Apply(node)
	// Gen then Kill, which is different from dataflow equation
	for _k := range *switcher.Gen {
		if !util.Collision(outMap, _k) {
			(*outMap)[_k] = true
		}
	}
	for _k := range *outMap {
		k, _ := _k.(ast.Expr)
		ast.Inspect(k, func(_n ast.Node) bool {
			switch n := _n.(type) {
			case *ast.Ident:
				if _, ok := (*switcher.Kill)[n.Name]; ok {
					delete(*outMap, _k)
				}
			}
			return true
		})
	}
}

// NewInitalFlow returns a new flow
func (a *AvailableExpressionsFlowAnalysis) NewInitalFlow() *map[any]any {
	m := make(map[any]any)
	return &m
}

// EntryInitalFlow returns a new flow for entry
func (a *AvailableExpressionsFlowAnalysis) EntryInitalFlow() *map[any]any { return a.NewInitalFlow() }

// Copy copy from srcMap to dstMap
func (a *AvailableExpressionsFlowAnalysis) Copy(srcMap *map[any]any, dstMap *map[any]any) {
	for k, v := range *srcMap {
		(*dstMap)[k] = v
	}
}

// MergeInto merge from in to inout based on node
func (a *AvailableExpressionsFlowAnalysis) MergeInto(node ast.Node, inout *map[any]any, in *map[any]any) {
	// Available Expressions is a Must problem, so only take intersection
	for k := range *inout {
		if !util.Collision(in, k) {
			delete(*inout, k)
		}
	}
}

// End handle result of analysis
func (a *AvailableExpressionsFlowAnalysis) End(universe []*entry.Entry) {
	for _, v := range universe {
		fmt.Println("outFlow of node: " + util.String(v.Data))
		for n := range *v.OutFlow {
			fmt.Println(util.String(n))
		}
	}
}

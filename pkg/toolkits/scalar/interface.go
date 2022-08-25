package scalar

import (
	"go/ast"

	"github.com/cokeBeer/goot/pkg/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/util/entry"
)

// FlowAnalysis represents a flow analysis
type FlowAnalysis interface {
	GetGraph() *graph.NodeGraph
	IsForward() bool
	FlowThrougth(inMap *map[any]any, node ast.Node, outMap *map[any]any)
	NewInitalFlow() *map[any]any
	EntryInitalFlow() *map[any]any
	Copy(srcMap *map[any]any, dstMap *map[any]any)
	MergeInto(node ast.Node, inout *map[any]any, in *map[any]any)
	End(universe []*entry.Entry)
}

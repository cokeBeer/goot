package scalar

import (
	"github.com/cokeBeer/goot/pkg/dataflow/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/dataflow/util/entry"
	"golang.org/x/tools/go/ssa"
)

// FlowAnalysis represents a flow analysis
type FlowAnalysis interface {
	GetGraph() *graph.UnitGraph
	IsForward() bool
	Computations() int
	FlowThrougth(inMap *map[any]any, unit ssa.Instruction, outMap *map[any]any)
	NewInitalFlow() *map[any]any
	EntryInitalFlow() *map[any]any
	Copy(srcMap *map[any]any, dstMap *map[any]any)
	MergeInto(Unit ssa.Instruction, inout *map[any]any, in *map[any]any)
	End(universe []*entry.Entry)
}

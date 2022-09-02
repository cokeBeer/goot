package graph

import "golang.org/x/tools/go/ssa"

// UnitGraph represents a graph based on ssa unit
type UnitGraph struct {
	Func        *ssa.Function
	UnitChain   []ssa.Instruction
	UnitToSuccs map[ssa.Instruction][]ssa.Instruction
	UnitToPreds map[ssa.Instruction][]ssa.Instruction
	Heads       []ssa.Instruction
	Tails       []ssa.Instruction
}

// New creates a UnitGraph
func New(f *ssa.Function) *UnitGraph {
	unitGraph := new(UnitGraph)
	unitGraph.Func = f
	unitGraph.UnitChain = make([]ssa.Instruction, 0)
	unitGraph.Heads = make([]ssa.Instruction, 0)
	if len(f.Blocks) != 0 {
		unitGraph.Heads = append(unitGraph.Heads, f.Blocks[0].Instrs[0])
	}
	unitGraph.Tails = make([]ssa.Instruction, 0)
	unitGraph.UnitToSuccs = make(map[ssa.Instruction][]ssa.Instruction)
	unitGraph.UnitToPreds = make(map[ssa.Instruction][]ssa.Instruction)
	for _, b := range f.Blocks {
		if len(b.Instrs) == 0 {
			continue
		}
		for i := 0; i < len(b.Instrs)-1; i++ {
			unitGraph.UnitChain = append(unitGraph.UnitChain, b.Instrs[i])
			unitGraph.UnitToSuccs[b.Instrs[i]] = append(unitGraph.UnitToSuccs[b.Instrs[i]], b.Instrs[i+1])
			unitGraph.UnitToPreds[b.Instrs[i+1]] = append(unitGraph.UnitToPreds[b.Instrs[i+1]], b.Instrs[i])
		}
		unitGraph.UnitChain = append(unitGraph.UnitChain, b.Instrs[len(b.Instrs)-1])
		if len(b.Succs) == 0 {
			unitGraph.Tails = append(unitGraph.Tails, b.Instrs[len(b.Instrs)-1])
			continue
		}
		for _, s := range b.Succs {
			t := s
			for len(t.Instrs) == 0 {
				t = t.Succs[0]
			}
			unitGraph.UnitToSuccs[b.Instrs[len(b.Instrs)-1]] = append(unitGraph.UnitToSuccs[b.Instrs[len(b.Instrs)-1]], t.Instrs[0])
			unitGraph.UnitToPreds[t.Instrs[0]] = append(unitGraph.UnitToPreds[t.Instrs[0]], b.Instrs[len(b.Instrs)-1])
		}
	}
	return unitGraph
}

// Size returns length of the UnitChain
func (g *UnitGraph) Size() int {
	return len(g.UnitChain)
}

// GetSuccs returns Succs of an instruction
func (g *UnitGraph) GetSuccs(inst ssa.Instruction) []ssa.Instruction {
	return g.UnitToSuccs[inst]
}

// GetPreds returns Preds of an instruction
func (g *UnitGraph) GetPreds(inst ssa.Instruction) []ssa.Instruction {
	return g.UnitToPreds[inst]
}

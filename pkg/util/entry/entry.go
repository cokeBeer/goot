package entry

import (
	"math"

	"golang.org/x/tools/go/ssa"
)

// Entry represents a base unit in a flow graph
type Entry struct {
	Data                    ssa.Instruction
	InFlow                  *map[any]any
	OutFlow                 *map[any]any
	In                      []*Entry
	Out                     []*Entry
	Number                  int
	IsRealStronglyConnected bool
}

// New creates an Entry
func New(u ssa.Instruction, pred *Entry) *Entry {
	entry := new(Entry)
	entry.In = []*Entry{pred}
	entry.Data = u
	entry.Number = math.MinInt
	entry.IsRealStronglyConnected = false
	return entry
}

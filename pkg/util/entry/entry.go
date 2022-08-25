package entry

import (
	"go/ast"
	"math"
)

type Entry struct {
	Data                    ast.Node
	InFlow                  *map[any]any
	OutFlow                 *map[any]any
	In                      []*Entry
	Out                     []*Entry
	Number                  int
	IsRealStronglyConnected bool
}

func New(u ast.Node, pred *Entry) *Entry {
	entry := new(Entry)
	entry.In = []*Entry{pred}
	entry.Data = u
	entry.Number = math.MinInt
	entry.IsRealStronglyConnected = false
	return entry
}

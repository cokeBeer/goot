package util

import "golang.org/x/tools/go/ssa"

// Collision check whether a node has appeared in flow
func Collision(flow *map[any]any, _n ssa.Instruction) bool {
	for _k := range *flow {
		switch k := _k.(type) {
		case ssa.Instruction:
			if k.String() == _n.String() {
				return true
			}
		}
	}
	return false
}

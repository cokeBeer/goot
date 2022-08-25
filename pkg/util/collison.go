package util

// Collision check whether a node has appeared in flow
func Collision(flow *map[any]any, _n any) bool {
	for _k := range *flow {
		if String(_k) == String(_n) {
			return true
		}
	}
	return false
}

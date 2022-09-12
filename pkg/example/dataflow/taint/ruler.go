package taint

import "github.com/cokeBeer/goot/pkg/example/dataflow/taint/rule"

// DummyRuler is a dummy rule.Ruler used for test
type DummyRuler struct {
	rule.BaseRuler
}

// NewDummyRuler returns a DummyRuler
func NewDummyRuler(moduleName string) *DummyRuler {
	dummyRuler := new(DummyRuler)
	dummyRuler.BaseRuler = *rule.NewBaseRuler(moduleName)
	return dummyRuler
}

// IsSource returns whether a node is a source
func (r *DummyRuler) IsSource(_f any) bool {
	switch node := _f.(type) {
	case *Node:
		if node.Function != nil {
			f := node.Function
			hit := 0
			for _, param := range f.Params {
				if param.Type().String() == "net/http.ResponseWriter" {
					hit++
				}
				if param.Type().String() == "*net/http.Request" {
					hit++
				}
				if hit >= 2 {
					return true
				}
			}
		}
	}
	return false
}

// passPropertry pass properties from a node to an edge
func passProperty(node *Node, edge *Edge) {
	if node.IsMethod {
		edge.ToIsMethod = true
	} else if node.IsStatic {
		edge.ToIsStatic = true
	} else if node.IsSignature {
		edge.ToIsSignature = true
	}
	if node.IsSink {
		edge.ToIsSink = true
	}
}

// decideProperty decide a node's properties by a ruler
func decidePropertry(node *Node, ruler rule.Ruler) {
	if ruler.IsIntra(node.Canonical) {
		node.IsIntra = true
	}
	if ruler.IsSource(node) {
		node.IsSource = true
	}
	if ruler.IsSink(node.Canonical) {
		node.IsSink = true
	}
}

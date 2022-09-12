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
			if len(f.Params) == 2 {
				if f.Params[0].Type().String() == "net/http.ResponseWriter" && f.Params[1].Type().String() == "*net/http.Request" {
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

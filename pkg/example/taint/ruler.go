package taint

import "github.com/cokeBeer/goot/pkg/example/taint/rule"

// DummyRuler is a dummy rule.Ruler used for test
type DummyRuler struct {
	rule.BaseRuler
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
	if ruler.IsIntro(node.Canonical) {
		node.IsIntra = true
	}
	if ruler.IsSource(node.Canonical) {
		node.IsSource = true
	}
	if ruler.IsSink(node.Canonical) {
		node.IsSink = true
	}
}

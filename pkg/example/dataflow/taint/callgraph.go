package taint

import (
	"strconv"

	"github.com/cokeBeer/goot/pkg/example/dataflow/taint/rule"
	"golang.org/x/tools/go/ssa"
)

// CallGraph represents a graph contain static call nodes and edges
type CallGraph struct {
	Nodes *map[string]*Node
	Edges *map[string]*Edge
}

// NewCallGraph returns a CallGraph
func NewCallGraph(allFuncs *map[*ssa.Function]bool, ruler rule.Ruler) *CallGraph {
	callGraph := new(CallGraph)
	nodes := make(map[string]*Node)
	edges := make(map[string]*Edge)
	callGraph.Nodes = &nodes
	callGraph.Edges = &edges
	for f := range *allFuncs {
		if f.Signature.Recv() != nil {
			node := &Node{Canonical: f.String(), Index: 0, Out: make([]*Edge, 0), In: make([]*Edge, 0)}
			decidePropertry(node, ruler)
			node.IsStatic = true
			(*callGraph.Nodes)[f.String()+"#"+strconv.Itoa(0)] = node
			n := f.Signature.Params().Len()
			for i := 0; i < n; i++ {
				node := &Node{Function: f, Canonical: f.String(), Index: i + 1, Out: make([]*Edge, 0), In: make([]*Edge, 0)}
				decidePropertry(node, ruler)
				node.IsStatic = true
				(*callGraph.Nodes)[f.String()+"#"+strconv.Itoa(i+1)] = node
			}
		} else {
			n := f.Signature.Params().Len()
			for i := 0; i < n; i++ {
				node := &Node{Function: f, Canonical: f.String(), Index: i, Out: make([]*Edge, 0), In: make([]*Edge, 0)}
				decidePropertry(node, ruler)
				node.IsStatic = true
				(*callGraph.Nodes)[f.String()+"#"+strconv.Itoa(i)] = node
			}
		}
	}
	return callGraph
}

// Node represents a taint node
type Node struct {
	Function    *ssa.Function
	IsSignature bool
	IsMethod    bool
	IsStatic    bool
	IsSource    bool
	IsSink      bool
	IsIntra     bool
	Canonical   string
	Index       int
	Out         []*Edge
	In          []*Edge
}

// Edge represents a taint edge
type Edge struct {
	From          string
	FromIndex     int
	To            string
	ToIndex       int
	ToIsMethod    bool
	ToIsSink      bool
	ToIsSignature bool
	ToIsStatic    bool
}

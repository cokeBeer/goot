package graph

import (
	"go/ast"

	"golang.org/x/tools/go/cfg"
)

// A NodeGraph represents a CFG in node format
type NodeGraph struct {
	Graph       *cfg.CFG
	Decl        *ast.FuncDecl
	NodeChain   []ast.Node
	NodeToSuccs map[ast.Node][]ast.Node
	NodeToPreds map[ast.Node][]ast.Node
	Heads       []ast.Node
	Tails       []ast.Node
}

// New returns a NodeGraph
func New(f *ast.FuncDecl, mayReturn ...func(call *ast.CallExpr) bool) *NodeGraph {
	nodeGraph := new(NodeGraph)
	nodeGraph.Decl = f
	var ret func(call *ast.CallExpr) bool
	if mayReturn == nil {
		ret = trival
	} else {
		ret = mayReturn[0]
	}
	g := cfg.New(f.Body, ret)
	nodeGraph.Graph = g
	nodeGraph.NodeChain = make([]ast.Node, 0)
	nodeGraph.Heads = make([]ast.Node, 0)
	nodeGraph.Heads = append(nodeGraph.Heads, g.Blocks[0].Nodes[0])
	nodeGraph.Tails = make([]ast.Node, 0)
	nodeGraph.NodeToPreds = make(map[ast.Node][]ast.Node)
	nodeGraph.NodeToSuccs = make(map[ast.Node][]ast.Node)
	for _, b := range g.Blocks {
		// skip if current block has no nodes
		if len(b.Nodes) == 0 {
			continue
		}
		// construct succs and preds except the last node
		for i := 0; i < len(b.Nodes)-1; i++ {
			nodeGraph.NodeChain = append(nodeGraph.NodeChain, b.Nodes[i])
			nodeGraph.NodeToPreds[b.Nodes[i+1]] = append(nodeGraph.NodeToPreds[b.Nodes[i+1]], b.Nodes[i])
			nodeGraph.NodeToSuccs[b.Nodes[i]] = append(nodeGraph.NodeToSuccs[b.Nodes[i]], b.Nodes[i+1])
		}
		nodeGraph.NodeChain = append(nodeGraph.NodeChain, b.Nodes[len(b.Nodes)-1])
		// skip if current block has no succs
		if len(b.Succs) == 0 {
			// last node of current block is an exit node
			nodeGraph.Tails = append(nodeGraph.Tails, b.Nodes[len(b.Nodes)-1])
			continue
		}
		// skip until a block has nodes, then construct succs and preds
		for _, s := range b.Succs {
			t := s
			for len(t.Nodes) == 0 {
				t = t.Succs[0]
			}
			nodeGraph.NodeToSuccs[b.Nodes[len(b.Nodes)-1]] = append(nodeGraph.NodeToSuccs[b.Nodes[len(b.Nodes)-1]], t.Nodes[0])
			nodeGraph.NodeToPreds[t.Nodes[0]] = append(nodeGraph.NodeToPreds[t.Nodes[0]], b.Nodes[len(b.Nodes)-1])
		}
	}
	return nodeGraph
}

// Size returns the number of nodes in a NodeGraph
func (g *NodeGraph) Size() int {
	return len(g.NodeChain)
}

// GetSuccs returns the succs of a node
func (g *NodeGraph) GetSuccs(n ast.Node) []ast.Node {
	return g.NodeToSuccs[n]
}

// GetPreds returns the preds of a node
func (g *NodeGraph) GetPreds(n ast.Node) []ast.Node {
	return g.NodeToPreds[n]
}

// Consider panic() and *.Fatal() as a return
func trival(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name != "panic"
	case *ast.SelectorExpr:
		return fun.Sel.Name != "Fatal"
	}
	return true
}

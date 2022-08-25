package switcher

import (
	"go/ast"

	"github.com/cokeBeer/goot/pkg/golang/switcher"
)

// LiveVariablesSwitcher represents a live variables switcher
type LiveVariablesSwitcher struct {
	switcher.BaseSwitcher
	Gen  *map[any]any
	Kill *map[any]any
}

// Apply contructs an LiveVariablesSwticher and calls switcher.Apply
func Apply(_n ast.Node) *LiveVariablesSwitcher {
	liveVariablesSwitcher := new(LiveVariablesSwitcher)
	gen := make(map[any]any)
	kill := make(map[any]any)
	liveVariablesSwitcher.Gen = &gen
	liveVariablesSwitcher.Kill = &kill
	switcher.Apply(liveVariablesSwitcher, _n)
	return liveVariablesSwitcher
}

// CaseBinaryExpr handles *ast.BinaryExpr
func (s *LiveVariablesSwitcher) CaseBinaryExpr(_n *ast.BinaryExpr) {
	ast.Inspect(_n, func(_n ast.Node) bool {
		switch n := _n.(type) {
		case *ast.Ident:
			(*s.Gen)[n.Name] = true
		}
		return true
	})
}

// CaseReturnStmt handles *ast.ReturnStmt
func (s *LiveVariablesSwitcher) CaseReturnStmt(_n *ast.ReturnStmt) {
	ast.Inspect(_n, func(_n ast.Node) bool {
		switch n := _n.(type) {
		case *ast.Ident:
			(*s.Gen)[n.Name] = true
		}
		return true
	})
}

// CaseAssignStmt handles *ast.AssignStmt
func (s *LiveVariablesSwitcher) CaseAssignStmt(n *ast.AssignStmt) {
	for _, e := range n.Lhs {
		s.CaseLHSExpr(e)
	}
	for _, e := range n.Rhs {
		s.CaseRHSExpr(e)
	}
}

// CaseLHSExpr handles *ast.Expr on the left hand side of *ast.AssignStmt
func (s *LiveVariablesSwitcher) CaseLHSExpr(_n ast.Expr) {
	switch n := (_n).(type) {
	case *ast.Ident:
		(*s.Kill)[n.Name] = true
	}
}

// CaseRHSExpr handles *ast.Expr on the right hand side of *ast.AssignStmt
func (s *LiveVariablesSwitcher) CaseRHSExpr(_n ast.Expr) {
	ast.Inspect(_n, func(_n ast.Node) bool {
		switch n := _n.(type) {
		case *ast.Ident:
			(*s.Gen)[n.Name] = true
		}
		return true
	})
}

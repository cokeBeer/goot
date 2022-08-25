package switcher

import (
	"go/ast"

	"github.com/cokeBeer/goot/pkg/golang/switcher"
)

// AvailableExpressionsSwitcher represents an available expressions switcher
type AvailableExpressionsSwitcher struct {
	switcher.BaseSwitcher
	Gen  *map[any]any
	Kill *map[any]any
}

// Apply contructs an AvailableExpressionsSwticher and calls switcher.Apply
func Apply(_n ast.Node) *AvailableExpressionsSwitcher {
	AvailableExpressionsSwitcher := new(AvailableExpressionsSwitcher)
	gen := make(map[any]any)
	kill := make(map[any]any)
	AvailableExpressionsSwitcher.Gen = &gen
	AvailableExpressionsSwitcher.Kill = &kill
	switcher.Apply(AvailableExpressionsSwitcher, _n)
	return AvailableExpressionsSwitcher
}

// CaseAssignStmt handles *ast.AssignStmt
func (s *AvailableExpressionsSwitcher) CaseAssignStmt(n *ast.AssignStmt) {
	for _, e := range n.Lhs {
		s.CaseLHSExpr(&e)
	}
	for _, e := range n.Rhs {
		s.CaseRHSExpr(&e)
	}
}

// CaseLHSExpr handles *ast.Expr on the left hand side of *ast.AssignStmt
func (s *AvailableExpressionsSwitcher) CaseLHSExpr(_n *ast.Expr) {
	switch n := (*_n).(type) {
	case *ast.Ident:
		(*s.Kill)[n.Name] = true
	}
}

// CaseRHSExpr handles *ast.Expr on the right hand side of *ast.AssignStmt
func (s *AvailableExpressionsSwitcher) CaseRHSExpr(_n *ast.Expr) {
	switch n := (*_n).(type) {
	case *ast.BinaryExpr:
		(*s.Gen)[n] = true
	}
}

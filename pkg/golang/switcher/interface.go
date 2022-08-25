package switcher

import "go/ast"

// Switcher represents a node swticher
type Switcher interface {
	CaseBadStmt(s *ast.BadStmt)
	CaseIncDecStmt(s *ast.IncDecStmt)
	CaseGoStmt(s *ast.GoStmt)
	CaseDeferStmt(s *ast.DeferStmt)
	CaseEmptyStmt(s *ast.EmptyStmt)
	CaseAssignStmt(s *ast.AssignStmt)
	CaseExprStmt(s *ast.ExprStmt)
	CaseReturnStmt(s *ast.ReturnStmt)

	CaseValueSpec(s *ast.ValueSpec)

	CaseBadExpr(s *ast.BadExpr)
	CaseIdent(s *ast.Ident)
	CaseEllipsis(s *ast.Ellipsis)
	CaseBasicLit(s *ast.BasicLit)
	CaseFuncLit(s *ast.FuncLit)
	CaseComposeLit(s *ast.CompositeLit)
	CaseParentExpr(s *ast.ParenExpr)
	CaseSelectorExpr(s *ast.SelectorExpr)
	CaseIndexExpr(s *ast.IndexExpr)
	CaseIndexListExpr(s *ast.IndexListExpr)
	CaseSliceExpr(s *ast.SliceExpr)
	CaseTypeAssertExpr(s *ast.TypeAssertExpr)
	CaseCallExpr(s *ast.CallExpr)
	CaseStarExpr(s *ast.StarExpr)
	CaseUnaryExpr(s *ast.UnaryExpr)
	CaseBinaryExpr(s *ast.BinaryExpr)
	CaseKeyValueExpr(s *ast.KeyValueExpr)
}

// Apply calls different methods based on type of ast.Node
func Apply(s Switcher, _n ast.Node) {
	switch n := _n.(type) {
	case *ast.BadStmt:
		s.CaseBadStmt(n)
	case *ast.IncDecStmt:
		s.CaseIncDecStmt(n)
	case *ast.GoStmt:
		s.CaseGoStmt(n)
	case *ast.DeferStmt:
		s.CaseDeferStmt(n)
	case *ast.EmptyStmt:
		s.CaseEmptyStmt(n)
	case *ast.AssignStmt:
		s.CaseAssignStmt(n)
	case *ast.ExprStmt:
		s.CaseExprStmt(n)
	case *ast.ReturnStmt:
		s.CaseReturnStmt(n)
	case *ast.ValueSpec:
		s.CaseValueSpec(n)
	case *ast.BadExpr:
		s.CaseBadExpr(n)
	case *ast.Ident:
		s.CaseIdent(n)
	case *ast.Ellipsis:
		s.CaseEllipsis(n)
	case *ast.BasicLit:
		s.CaseBasicLit(n)
	case *ast.FuncLit:
		s.CaseFuncLit(n)
	case *ast.CompositeLit:
		s.CaseComposeLit(n)
	case *ast.ParenExpr:
		s.CaseParentExpr(n)
	case *ast.SelectorExpr:
		s.CaseSelectorExpr(n)
	case *ast.IndexExpr:
		s.CaseIndexExpr(n)
	case *ast.IndexListExpr:
		s.CaseIndexListExpr(n)
	case *ast.SliceExpr:
		s.CaseSliceExpr(n)
	case *ast.TypeAssertExpr:
		s.CaseTypeAssertExpr(n)
	case *ast.CallExpr:
		s.CaseCallExpr(n)
	case *ast.StarExpr:
		s.CaseStarExpr(n)
	case *ast.UnaryExpr:
		s.CaseUnaryExpr(n)
	case *ast.BinaryExpr:
		s.CaseBinaryExpr(n)
	case *ast.KeyValueExpr:
		s.CaseKeyValueExpr(n)
	}
}

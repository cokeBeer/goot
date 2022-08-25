package switcher

import "go/ast"

// BaseSwitcher represents a base Switcher implementation
type BaseSwitcher struct {
}

// CaseBadStmt represents a base CaseBadStmt implementation
func (b *BaseSwitcher) CaseBadStmt(s *ast.BadStmt) {}

// CaseIncDecStmt represents a base CaseIncDecStmt implementation
func (b *BaseSwitcher) CaseIncDecStmt(s *ast.IncDecStmt) {}

// CaseGoStmt represents a base CaseGoStmt implementation
func (b *BaseSwitcher) CaseGoStmt(s *ast.GoStmt) {}

// CaseDeferStmt represents a base CaseDeferStmt implementation
func (b *BaseSwitcher) CaseDeferStmt(s *ast.DeferStmt) {}

// CaseEmptyStmt represents a base CaseEmptyStmt implementation
func (b *BaseSwitcher) CaseEmptyStmt(s *ast.EmptyStmt) {}

// CaseAssignStmt represents a base CaseAssignStmt implementation
func (b *BaseSwitcher) CaseAssignStmt(s *ast.AssignStmt) {}

// CaseExprStmt represents a base CaseExprStmt implementation
func (b *BaseSwitcher) CaseExprStmt(s *ast.ExprStmt) {}

// CaseReturnStmt represents a base CaseReturnStmt implementation
func (b *BaseSwitcher) CaseReturnStmt(s *ast.ReturnStmt) {}

// CaseValueSpec represents a base CaseValueSpec implementation
func (b *BaseSwitcher) CaseValueSpec(s *ast.ValueSpec) {}

// CaseBadExpr represents a base CaseBadExpr implementation
func (b *BaseSwitcher) CaseBadExpr(s *ast.BadExpr) {}

// CaseIdent represents a base CaseIdent implementation
func (b *BaseSwitcher) CaseIdent(s *ast.Ident) {}

// CaseEllipsis represents a base CaseEllipsis implementation
func (b *BaseSwitcher) CaseEllipsis(s *ast.Ellipsis) {}

// CaseBasicLit represents a base CaseBasicLit implementation
func (b *BaseSwitcher) CaseBasicLit(s *ast.BasicLit) {}

// CaseFuncLit represents a base CaseFuncLit implementation
func (b *BaseSwitcher) CaseFuncLit(s *ast.FuncLit) {}

// CaseComposeLit represents a base CaseComposeLit implementation
func (b *BaseSwitcher) CaseComposeLit(s *ast.CompositeLit) {}

// CaseParentExpr represents a base CaseParentExpr implementation
func (b *BaseSwitcher) CaseParentExpr(s *ast.ParenExpr) {}

// CaseSelectorExpr represents a base CaseSelectorExpr implementation
func (b *BaseSwitcher) CaseSelectorExpr(s *ast.SelectorExpr) {}

// CaseIndexExpr represents a base CaseIndexExpr implementation
func (b *BaseSwitcher) CaseIndexExpr(s *ast.IndexExpr) {}

// CaseIndexListExpr represents a base CaseIndexListExpr implementation
func (b *BaseSwitcher) CaseIndexListExpr(s *ast.IndexListExpr) {}

// CaseSliceExpr represents a base CaseSliceExpr implementation
func (b *BaseSwitcher) CaseSliceExpr(s *ast.SliceExpr) {}

// CaseTypeAssertExpr represents a base CaseTypeAssertExpr implementation
func (b *BaseSwitcher) CaseTypeAssertExpr(s *ast.TypeAssertExpr) {}

// CaseCallExpr represents a base CaseCallExpr implementation
func (b *BaseSwitcher) CaseCallExpr(s *ast.CallExpr) {}

// CaseStarExpr represents a base CaseStarExpr implementation
func (b *BaseSwitcher) CaseStarExpr(s *ast.StarExpr) {}

// CaseUnaryExpr represents a base CaseUnaryExpr implementation
func (b *BaseSwitcher) CaseUnaryExpr(s *ast.UnaryExpr) {}

// CaseBinaryExpr represents a base CaseBinaryExpr implementation
func (b *BaseSwitcher) CaseBinaryExpr(s *ast.BinaryExpr) {}

// CaseKeyValueExpr represents a base CaseKeyValueExpr implementation
func (b *BaseSwitcher) CaseKeyValueExpr(s *ast.KeyValueExpr) {}

<div align="center">
  <img src="goot-logo.png" height="200" style="border-radius:10px;">

 # goot
</div>

## Update 
a new version based on SSA is on the way

## What is goot?

goot is a static analysis framework for Go. goot is easy-to-learn, easy-to-use and highly extensible,  allowing you to easily develop new analyses on top of it.

Currently, goot provides the following major analysis components (and more analysis are on the way):

- Control/Data-flow analysis framework
  - Control-flow graph construction
  - Classic data-flow analyses, e.g., live variables analysis, available expressions analysis
  - Your dataflow analyses

## How to use?

first intall goot by

```
go get -u github.com/cokeBeer/goot
```

then create two structs implementing  `pkg/toolkits/scalar.FlowAnalysis` interface

```go
// FlowAnalysis represents a flow analysis
type FlowAnalysis interface {
	GetGraph() *graph.NodeGraph
	IsForward() bool
	FlowThrougth(inMap *map[any]any, node ast.Node, outMap *map[any]any)
	NewInitalFlow() *map[any]any
	EntryInitalFlow() *map[any]any
	Copy(srcMap *map[any]any, dstMap *map[any]any)
	MergeInto(node ast.Node, inout *map[any]any, in *map[any]any)
	End(universe []*entry.Entry)
}
```

and `pkg/golang/switcher.Switcher` interface seperately

```go
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
```

an easy way to implement them is using compose like `pkg/toolkits/scalar.BaseFlowAnalysis`

```go
// AvailableExpressionsFlowAnalysis represents an available expressions analysis
type AvailableExpressionsFlowAnalysis struct {
	scalar.BaseFlowAnalysis
}
```

and `pkg/golang/switcher.BaseSwitcher`

```go
// AvailableExpressionsSwitcher represents an available expressions switcher
type AvailableExpressionsSwitcher struct {
	switcher.BaseSwitcher
	Gen  *map[any]any
	Kill *map[any]any
}
```

these can make you focus on the core methods you really need to design carefully in specific analyses

some examples can be found in `pkg/example` package

and you can learn **how to run** an analysis from  `cmd` package

## Presentation

run `cmd/availableexpressionsanalysis` on

```go
package main

func main(a int, b int, x int, y int) int {
	x = a + b
	y = a * b
	for y > a {
		a = a + 1
		x = a + b
	}
	return x
}
```

you can get

```
outFlow of node: x = a + b
a + b
outFlow of node: y = a * b
a + b
a * b
outFlow of node: y > a
a + b
outFlow of node: return x
a + b
outFlow of node: a = a + 1
outFlow of node: x = a + b
a + b
```

run `cmd/livevariablesanalysis` on the same code, you can get

```
outFlow of node: return x
x
outFlow of node: y > a
a
b
x
y
outFlow of node: x = a + b
y
a
b
outFlow of node: a = a + 1
b
y
a
outFlow of node: y = a * b
b
a
x
outFlow of node: x = a + b
a
b
```

## TIPS

- goot's api is similar to [soot](https://github.com/soot-oss/soot), so if you wonder how goot's api work, you can [learn soot](https://github.com/soot-oss/soot/wiki/Implementing-an-intra-procedural-data-flow-analysis-in-Soot) first
- goot uses `*map[any]any` as flow and `ast.Node` as unit, so please be careful of type assertion

## Thanks

- [soot](https://github.com/soot-oss/soot)
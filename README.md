<div align="center">
  <img src="goot-logo.png" height="200" style="border-radius:10px;">

 # goot
</div>

- [goot](#goot)
	- [What is goot?](#what-is-goot)
	- [Get started](#get-started)
	- [Use passthrough analysis](#use-passthrough-analysis)
	- [Use as a framework](#use-as-a-framework)
	- [Presentation](#presentation)
	- [Tips](#tips)
	- [Thanks](#thanks)
## What is goot?

[goot](https://github.com/cokeBeer/goot) is a static analysis framework for Go. goot is easy-to-learn, easy-to-use and highly extensible, allowing you to easily develop new analyses on top of it.

Currently, goot provides the following major analysis components (and more analyses are on the way):

- Control/Data-flow analysis framework
  - Control-flow graph construction
  - Classic data-flow analyses, e.g., constant propagtion analysis, taint passthrough analysis
  - Your dataflow analyses

## Get started

First intall goot by

```
go get -u github.com/cokeBeer/goot
```

Then you can copy examples from package `cmd` to your project \
For example, copy `cmd/constantpropagationanalysis`
```go
package main

import (
	"github.com/cokeBeer/goot/pkg/example/constantpropagation"
)

const src = `package main

func Hello(a int, b int) bool {
	a = 1
	x := a + 3
	y := b + 2
	if x > y {
		x = x + 1
	} else {
		x = y + 1
	}
	w := x > 0
	return w
}`

func main() {
	runner := &constantpropagation.Runner{Src: src, Function: "Hello"}
	runner.Run()
}
```
Run the code, and you will get a constant propagtion analysis [result](#presentation) output to console
##  Use passthrough analysis
Write code below in your project
```go
package main

import "github.com/cokeBeer/goot/pkg/example/taint"

func main() {
	runner := taint.NewRunner("your-module-path")
	runner.SrcPath = ""
	runner.DstPath = "passthrough.json"
	runner.Debug = true
	runner.Run()
}
```
Run the code, and you will get a `passthrough.json` in the same directory, which contains taint passthrough information of all functions in your project\
I hava generated an output for `fmt` in [cmd/taintanalysis/fmt.json](cmd/taintanalysis/fmt.json)\
You can see key `fmt.Sprintf` holds the value `[0,1]`
```json
{
    "fmt.Sprintf": [
        [0, 1]
    ]
}
```
This means the first parameter's taint and the second paramter's taint are passed to the first return value


## Use as a framework
To use goot as a framework,  first create two structs implementing  `pkg/toolkits/scalar.FlowAnalysis` interface

```go
// FlowAnalysis represents a flow analysis
type FlowAnalysis interface {
	GetGraph() *graph.UnitGraph
	IsForward() bool
	Computations() int
	FlowThrougth(inMap *map[any]any, unit ssa.Instruction, outMap *map[any]any)
	NewInitalFlow() *map[any]any
	EntryInitalFlow() *map[any]any
	Copy(srcMap *map[any]any, dstMap *map[any]any)
	MergeInto(Unit ssa.Instruction, inout *map[any]any, in *map[any]any)
	End(universe []*entry.Entry)
}
```

and `pkg/golang/switcher.Switcher` interface seperately

```go
// Switcher represents a ssa instruction switcher
type Switcher interface {
	CaseAlloc(inst *ssa.Alloc)
	CasePhi(inst *ssa.Phi)
	CaseCall(inst *ssa.Call)
	CaseBinOp(inst *ssa.BinOp)
	CaseUnOp(inst *ssa.UnOp)
	...
	CaseGo(inst *ssa.Go)
	CaseDefer(inst *ssa.Defer)
	CaseSend(inst *ssa.Send)
	CaseStore(inst *ssa.Store)
	CaseMapUpdate(inst *ssa.MapUpdate)
	CaseDebugRef(inst *ssa.DebugRef)
}
```

Don't worry for these apis. An easy way to implement them is using compose like `pkg/toolkits/scalar.BaseFlowAnalysis`

```go
// ConstantPropagationAnalysis represents a constant propagtion analysis
type ConstantPropagationAnalysis struct {
	scalar.BaseFlowAnalysis
	constantPropagationSwitcher *ConstantPropagationSwitcher
}
```

and `pkg/golang/switcher.BaseSwitcher`

```go
// ConstantPropagationSwitcher represents a constant propagtion switcher
type ConstantPropagationSwitcher struct {
	switcher.BaseSwitcher
	constanctPropagationAnalysis *ConstantPropagationAnalysis
	inMap                        *map[any]any
	outMap                       *map[any]any
}
```

These can make you focus on the core methods you really need to design carefully in specific analyses

Some examples can be found in `pkg/example` package

And you can learn **how to run** an analysis from  `cmd` package

## Presentation

This is the output of `cmd/constantpropagationanalysis`\
The first part is the ssa and the second part is the constant propagation on ssa
```
# Name: constantpropagtionanalysis.Hello
# Package: constantpropagtionanalysis
# Location: 3:6
func Hello(a int, b int) bool:
0:                                                                entry P:0 S:2
        t0 = 1:int + 3:int                                                  int
        t1 = b + 2:int                                                      int
        t2 = t0 > t1                                                       bool
        if t2 goto 1 else 3
1:                                                              if.then P:1 S:1
        t3 = t0 + 1:int                                                     int
        jump 2
2:                                                              if.done P:2 S:0
        t4 = phi [1: t3, 3: t6] #x                                          int
        t5 = t4 > 0:int                                                    bool
        return t5
3:                                                              if.else P:1 S:1
        t6 = t1 + 1:int                                                     int
        jump 2

constant fact for instruction: 1:int + 3:int
a=UNDEF b=UNDEF t0=4 

constant fact for instruction: b + 2:int
a=UNDEF b=UNDEF t0=4 t1=UNDEF 

constant fact for instruction: t0 > t1
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF 

constant fact for instruction: if t2 goto 1 else 3
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF 

constant fact for instruction: t1 + 1:int
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t6=UNDEF 

constant fact for instruction: jump 2
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t6=UNDEF 

constant fact for instruction: t0 + 1:int
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t3=5 

constant fact for instruction: jump 2
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t3=5 

constant fact for instruction: phi [1: t3, 3: t6] #x
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t3=5 t4=5 t6=UNDEF 

constant fact for instruction: t4 > 0:int
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t3=5 t4=5 t5=NAC t6=UNDEF 

constant fact for instruction: return t5
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t3=5 t4=5 t5=NAC t6=UNDEF 
```

## Tips

- goot's api is similar to [soot](https://github.com/soot-oss/soot), so if you wonder how goot's api work, you can [learn soot](https://github.com/soot-oss/soot/wiki/Implementing-an-intra-procedural-data-flow-analysis-in-Soot) first
- goot uses `*map[any]any` as flow and `ssa.Instruction` as unit, so please be careful of type assertion

## Thanks

- [soot](https://github.com/soot-oss/soot)
- [Tai-e](https://github.com/pascal-lab/Tai-e)

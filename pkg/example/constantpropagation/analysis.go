package constantpropagation

import (
	"fmt"
	"os"
	"sort"

	"github.com/cokeBeer/goot/pkg/golang/switcher"
	"github.com/cokeBeer/goot/pkg/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/toolkits/scalar"
	"github.com/cokeBeer/goot/pkg/util/entry"
	"github.com/dnote/color"
	"golang.org/x/tools/go/ssa"
)

// ConstantPropagationAnalysis represents a constant propagtion analysis
type ConstantPropagationAnalysis struct {
	scalar.BaseFlowAnalysis
	constantPropagationSwitcher *ConstantPropagationSwitcher
}

// New creates a ConstantPropagationAnalysis
func New(g *graph.UnitGraph) *ConstantPropagationAnalysis {
	constanctPropagationAnalysis := new(ConstantPropagationAnalysis)
	constanctPropagationAnalysis.BaseFlowAnalysis = *scalar.NewBase(g)
	constantPropagationSwitcher := new(ConstantPropagationSwitcher)
	constantPropagationSwitcher.BaseSwitcher = *new(switcher.BaseSwitcher)
	constanctPropagationAnalysis.constantPropagationSwitcher = constantPropagationSwitcher
	constantPropagationSwitcher.constanctPropagationAnalysis = constanctPropagationAnalysis
	constanctPropagationAnalysis.Graph.Func.WriteTo(os.Stdout)
	return constanctPropagationAnalysis
}

// NewInitalFlow returns a new flow
func (a *ConstantPropagationAnalysis) NewInitalFlow() *map[any]any {
	m := make(map[any]any)
	for _, v := range a.Graph.Func.Params {
		m[v.Name()] = "UNDEF"
	}
	return &m
}

// FlowThrougth calculate outMap based on inMap and unit
func (a *ConstantPropagationAnalysis) FlowThrougth(inMap *map[any]any, unit ssa.Instruction, outMap *map[any]any) {
	a.Copy(inMap, outMap)
	a.apply(inMap, unit, outMap)
}

// End handle result of analysis
func (a *ConstantPropagationAnalysis) End(universe []*entry.Entry) {
	for _, v := range universe {
		color.Set(color.FgGreen)
		fmt.Println("constant fact for instruction: " + (*v).Data.String())
		color.Unset()
		keys := make([]string, len(*v.OutFlow))
		i := 0
		for k := range *v.OutFlow {
			keys[i] = k.(string)
			i++
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%v=%v ", k, (*v.OutFlow)[k])
		}
		fmt.Println()
		fmt.Println()
	}
}

func (a *ConstantPropagationAnalysis) apply(inMap *map[any]any, inst ssa.Instruction, outMap *map[any]any) {
	a.constantPropagationSwitcher.inMap = inMap
	a.constantPropagationSwitcher.outMap = outMap
	switcher.Apply(a.constantPropagationSwitcher, inst)
}

package taint

import (
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// Imethod represents an interface method I.m.
// (There's no go/types object for it;
// a *types.Func may be shared by many interfaces due to interface embedding.)
type Imethod struct {
	I  *types.Interface
	id string
}

// InterfaceHierarchy represents implementation relations
type InterfaceHierarchy struct {
	methodsMemo   *map[Imethod][]*ssa.Function
	methodsByName *map[string][]*ssa.Function
}

// LookupMethods returns an interface method's implementations
func (i *InterfaceHierarchy) LookupMethods(I *types.Interface, m *types.Func) []*ssa.Function {
	id := m.Id()
	methods, ok := (*i.methodsMemo)[Imethod{I, id}]
	if !ok {
		for _, f := range (*i.methodsByName)[m.Name()] {
			C := f.Signature.Recv().Type() // named or *named
			if types.Implements(C, I) {
				methods = append(methods, f)
			}
		}
		(*i.methodsMemo)[Imethod{I, id}] = methods
	}
	return methods
}

// Build returns an InterfaceHierarchy
func Build(allFuncs *map[*ssa.Function]bool) *InterfaceHierarchy {

	// methodsByName contains all methods,
	// grouped by name for efficient lookup.
	// (methodsById would be better but not every SSA method has a go/types ID.)
	methodsByName := make(map[string][]*ssa.Function)

	// methodsMemo records, for every abstract method call I.m on
	// interface type I, the set of concrete methods C.m of all
	// types C that satisfy interface I.
	//
	// Abstract methods may be shared by several interfaces,
	// hence we must pass I explicitly, not guess from m.
	//
	// methodsMemo is just a cache, so it needn't be a typeutil.Map.
	methodsMemo := make(map[Imethod][]*ssa.Function)

	for f := range *allFuncs {
		if f.Signature.Recv() != nil {
			methodsByName[f.Name()] = append(methodsByName[f.Name()], f)
		}
	}
	return &InterfaceHierarchy{methodsMemo: &methodsMemo, methodsByName: &methodsByName}
}

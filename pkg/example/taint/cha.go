package taint

import (
	"go/types"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

// Imethod represents an interface method I.m.
// (There's no go/types object for it;
// a *types.Func may be shared by many interfaces due to interface embedding.)
type Imethod struct {
	I  *types.Interface
	id string
}

// InterfaceHierarchy represents implemetation relations
type InterfaceHierarchy struct {
	funcsBySig    *typeutil.Map
	methodsMemo   *map[Imethod][]*ssa.Function
	methodsByName *map[string][]*ssa.Function
}

// LookupMethods returns an interface method's implemetations
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

// LookupFuncs returns
func (i *InterfaceHierarchy) LookupFuncs(signature *types.Signature) []*ssa.Function {
	funcs := i.funcsBySig.At(signature)
	if funcs == nil {
		return nil
	}
	return funcs.([]*ssa.Function)
}

// Build returns an InterfaceHierarchy
func Build(allFuncs *map[*ssa.Function]bool) *InterfaceHierarchy {

	// funcsBySig contains all functions, keyed by signature.  It is
	// the effective set of address-taken functions used to resolve
	// a dynamic call of a particular signature.
	var funcsBySig typeutil.Map // value is []*ssa.Function

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
		if f.Signature.Recv() == nil {
			if f.Signature.Recv() == nil {
				// Package initializers can never be address-taken.
				if f.Name() == "init" && f.Synthetic == "package initializer" {
					continue
				}
				funcs, _ := funcsBySig.At(f.Signature).([]*ssa.Function)
				funcs = append(funcs, f)
				funcsBySig.Set(f.Signature, funcs)
			} else {
				methodsByName[f.Name()] = append(methodsByName[f.Name()], f)
			}
		}
	}
	return &InterfaceHierarchy{funcsBySig: &funcsBySig, methodsMemo: &methodsMemo, methodsByName: &methodsByName}
}

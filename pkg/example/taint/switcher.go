package taint

import (
	"go/token"
	"go/types"
	"strconv"

	"github.com/cokeBeer/goot/pkg/golang/switcher"
	"golang.org/x/tools/go/ssa"
)

// TaintSwitcher represents a switcher for taint analysis
type TaintSwitcher struct {
	switcher.BaseSwitcher
	taintAnalysis *TaintAnalysis
	inMap         *map[any]any
	outMap        *map[any]any
}

// CaseAlloc accepts a Alloc instruction
func (s *TaintSwitcher) CaseAlloc(inst *ssa.Alloc) {
	(*s.outMap)[inst.Name()] = make(map[string]bool)
}

// CaseBinOp accepts a BinOp instruction
func (s *TaintSwitcher) CaseBinOp(inst *ssa.BinOp) {
	// update new taint by both inst.X and inst.Y
	newTaint := make(map[string]bool)
	// update taint by inst.X
	switch x := (inst.X).(type) {
	case *ssa.Parameter:
		// for parameter, just pass its name
		// actually, modification of parameter will generate new var
		// so don't worry about changes of parameter's taints
		// for receiver, the correctness also holds
		newTaint[inst.X.Name()] = true
	case
		*ssa.Alloc,
		*ssa.BinOp,
		*ssa.Call,
		*ssa.ChangeType,
		*ssa.ChangeInterface,
		*ssa.Convert,
		*ssa.Extract,
		*ssa.Field,
		*ssa.FieldAddr,
		*ssa.Index,
		*ssa.IndexAddr,
		*ssa.Lookup,
		*ssa.MakeChan,
		*ssa.MakeInterface,
		*ssa.MakeMap,
		*ssa.MakeSlice,
		*ssa.Next,
		*ssa.Range,
		*ssa.Slice,
		*ssa.TypeAssert,
		*ssa.UnOp,
		*ssa.Phi:
		// for other value instructions, pass old taints to new taints
		oldTaint := (*s.outMap)[x.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	// also update taint by inst.Y
	switch y := (inst.Y).(type) {
	case *ssa.Parameter:
		newTaint[y.Name()] = true
	case *ssa.Alloc,
		*ssa.BinOp,
		*ssa.Call,
		*ssa.ChangeType,
		*ssa.ChangeInterface,
		*ssa.Convert,
		*ssa.Extract,
		*ssa.Field,
		*ssa.FieldAddr,
		*ssa.Index,
		*ssa.IndexAddr,
		*ssa.Lookup,
		*ssa.MakeChan,
		*ssa.MakeInterface,
		*ssa.MakeMap,
		*ssa.MakeSlice,
		*ssa.Next,
		*ssa.Range,
		*ssa.Slice,
		*ssa.TypeAssert,
		*ssa.UnOp,
		*ssa.Phi:
		oldTaint := (*s.outMap)[y.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	(*s.outMap)[inst.Name()] = newTaint
}

// CaseCall accepts a Call instruction
func (s *TaintSwitcher) CaseCall(inst *ssa.Call) {
	c := s.taintAnalysis.config
	container := c.PassThroughContainer
	init := s.taintAnalysis.initMap
	switch v := (inst.Call.Value).(type) {
	case *ssa.Field:
		// caller can be a field from a struct
		// we consider it as an interface
		m := inst.Call.Method
		s.passInvokeTaint(m, inst)
	case *ssa.FreeVar:
		// caller can be a free var from closure
		// we consider it as an interface
		// e.g. bound$Write
		m := inst.Call.Method
		s.passInvokeTaint(m, inst)
	case *ssa.Lookup:
		// caller can be a value from map
		if inst.Call.Method == nil {
			// if it is a function, its signature information is in inst.Call.Value
			typ := v.X.Type().Underlying().(*types.Map).Elem()
			if p, ok := typ.Underlying().(*types.Pointer); ok {
				// anonymous function pointer
				m := p.Elem().Underlying().(*types.Signature)
				s.passFuncParamTaint(m, inst)
			} else {
				// anonymous function
				m := typ.Underlying().(*types.Signature)
				s.passFuncParamTaint(m, inst)
			}
		} else {
			// if it is an interface
			m := inst.Call.Method
			s.passInvokeTaint(m, inst)
		}
	case *ssa.MakeInterface:
		// caller can be a MakeInterface instruction
		// we consider it as an interface
		m := inst.Call.Method
		s.passInvokeTaint(m, inst)
	case *ssa.TypeAssert:
		// caller can be a TypeAssert instruction
		m := inst.Call.Method
		s.passInvokeTaint(m, inst)
	case *ssa.UnOp:
		// caller can be a UnOp instruction
		switch x := (v.X).(type) {
		case *ssa.UnOp:
			// its inst.X can be another UnOp instruction
			switch (x.X).(type) {
			case *ssa.IndexAddr:
				// this case is special
				// when use range over an interface pointer slice, it will hanppend
				// e.g. golang.org/x/tools/go/ssa/sanity.go checkBlock
				if inst.Call.Method != nil {
					// we consider is as a interface
					m := inst.Call.Method
					s.passInvokeTaint(m, inst)
				}
			default:
				if inst.Call.Method != nil {
					// we consider is as a interface
					m := inst.Call.Method
					s.passInvokeTaint(m, inst)
				}
			}
		case *ssa.FreeVar:
			// its inst.X can be a free var
			if inst.Call.Method == nil {
				// if it is a function, its signature information is in inst.Call.Value
				typ := x.Type()
				if p, ok := typ.Underlying().(*types.Pointer); ok {
					// anonymous function pointer
					m := p.Elem().Underlying().(*types.Signature)
					s.passFuncParamTaint(m, inst)
				} else {
					// anonymous function
					m := typ.Underlying().(*types.Signature)
					s.passFuncParamTaint(m, inst)
				}
			} else {
				// if it is an interface
				m := inst.Call.Method
				s.passInvokeTaint(m, inst)
			}
		case *ssa.Global:
			// its inst.X can be a global anonymous function or a global anonymous interface
			f, ok := (*init)[x.String()]
			if ok {
				// anonymous function that has been declared in source
				s.passCallTaint(f, inst)
			} else if inst.Call.Method != nil {
				// a global anonymous interface created by function return
				// e.g. go/types/universe.go universeAny = Universe.Lookup("any")
				m := inst.Call.Method
				s.passInvokeTaint(m, inst)
			} else {
				// anonymous function in assembly code
				// or some global anonymous functios failed to be recorded
				// e.g. golang.org/x/tools/internal/imports/fix.go fixImports
				m := x.Type().(*types.Pointer).Elem().Underlying().(*types.Signature)
				s.passFuncParamTaint(m, inst)
			}
		case *ssa.Alloc:
			// its inst.X can be a local anonymous function or a local anonymous interface
			if inst.Call.Method == nil {
				// if it is a function, its signature information is in inst.Call.Value
				// we try to find its *ssa.Function in referrers first
				// e.g. runtime/mpagealloc_64bit.go sysGrow
				ref := false
				for _, v := range *x.Referrers() {
					if store, ok := v.(*ssa.Store); ok {
						if f, ok := store.Val.(*ssa.Function); ok {
							// if a function stored to inst.X
							ref = ok
							_, ok = (*container)[f.String()]
							if !ok {
								Run(f, c)
							}
							s.passCallTaint(f, inst)
						} else if closure, ok := store.Val.(*ssa.MakeClosure); ok {
							if f, ok := closure.Fn.(*ssa.Function); ok {
								// if a closure stored to inst.X, retrive its Fn
								ref = ok
								_, ok = (*container)[f.String()]
								if !ok {
									Run(f, c)
								}
								s.passCallTaint(f, inst)
							}
						}
					}
				}
				if !ref {
					// if we can't find a *ssa.Function
					typ := x.Type()
					if p, ok := typ.Underlying().(*types.Pointer); ok {
						m := p.Elem().Underlying().(*types.Signature)
						s.passFuncParamTaint(m, inst)
					}
				}
			} else {
				// interface
				m := inst.Call.Method
				s.passInvokeTaint(m, inst)
			}
		case *ssa.FieldAddr:
			// its inst.X can be a struct field, represents an anonymous function or an anonymous interface
			// the struct can comes from reveiver or parameter
			if inst.Call.Method == nil {
				field := x.X.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Struct).Field(x.Field)
				typ := field.Type()
				if p, ok := typ.Underlying().(*types.Pointer); ok {
					// function pointer
					m := p.Elem().Underlying().(*types.Signature)
					s.passFuncParamTaint(m, inst)
				} else {
					// function
					m := typ.Underlying().(*types.Signature)
					s.passFuncParamTaint(m, inst)
				}
			} else {
				// interface
				m := inst.Call.Method
				s.passInvokeTaint(m, inst)
			}
		case *ssa.IndexAddr:
			// its inst.X can be a slice cell, represents an anonymous function or an anonymous interface
			if inst.Call.Method == nil {
				if slice, ok := x.X.Type().Underlying().(*types.Slice); ok {
					// if inst.X.X's underlying type is a slice
					typ := slice.Elem()
					if p, ok := typ.Underlying().(*types.Pointer); ok {
						// function pointer
						m := p.Elem().Underlying().(*types.Signature)
						s.passFuncParamTaint(m, inst)
					} else {
						// function
						m := typ.Underlying().(*types.Signature)
						s.passFuncParamTaint(m, inst)
					}
				}
				if pointer, ok := x.X.Type().Underlying().(*types.Pointer); ok {
					// if inst.X.X's underlying type is a pointer
					if array, ok := pointer.Elem().Underlying().(*types.Array); ok {
						// pointer points to an array
						// e.g. html/template/escape.go contextAfterText transitionFunc
						if p, ok := array.Elem().Underlying().(*types.Pointer); ok {
							// function pointer
							m := p.Elem().Underlying().(*types.Signature)
							s.passFuncParamTaint(m, inst)
						} else {
							// function
							m := array.Elem().Underlying().(*types.Signature)
							s.passFuncParamTaint(m, inst)
						}
					} else {
						// pointer pointers to a anonymous function
						m := pointer.Elem().Underlying().(*types.Signature)
						s.passFuncParamTaint(m, inst)
					}
				}
			} else {
				// interface
				m := inst.Call.Method
				s.passInvokeTaint(m, inst)
			}
		case *ssa.Extract:
			// its inst.X can be an Extract instruction
			// in this case, the function should hava more than one return value
			if inst.Call.Method == nil {
				// if it is a function, its signature information is in inst.Call.Value
				typ := x.Type()
				if p, ok := typ.Underlying().(*types.Pointer); ok {
					// function pointer
					m := p.Elem().Underlying().(*types.Signature)
					s.passFuncParamTaint(m, inst)
				} else {
					// function
					m := typ.Underlying().(*types.Signature)
					s.passFuncParamTaint(m, inst)
				}
			} else {
				// interface
				m := inst.Call.Method
				s.passInvokeTaint(m, inst)
			}
		case *ssa.Call:
			if inst.Call.Method != nil {
				// we consider is as a interface
				m := inst.Call.Method
				s.passInvokeTaint(m, inst)
			}
		default:
			if inst.Call.Method != nil {
				// we consider is as a interface
				m := inst.Call.Method
				s.passInvokeTaint(m, inst)
			}
		}
	case *ssa.Phi:
		// caller can be a Phi instruction
		if inst.Call.Method == nil {
			// if it is a function, its signature information is in inst.Call.Value
			// we choose first edge here
			m := v.Edges[0].Type().Underlying().(*types.Signature)
			s.passFuncParamTaint(m, inst)
		} else {
			// interface
			m := inst.Call.Method
			s.passInvokeTaint(m, inst)
		}
	case *ssa.MakeClosure:
		// caller can be a MakeClosure instruction
		if inst.Call.Method == nil {
			// if it is a function, its signature information is in inst.Call.Value
			m := v.Type().Underlying().(*types.Signature)
			s.passFuncParamTaint(m, inst)
		} else {
			// interface
			m := inst.Call.Method
			s.passInvokeTaint(m, inst)
		}
	case *ssa.Call:
		// caller can be a Call instruction
		if inst.Call.Method == nil {
			// if it is a function, its signature information is in inst.Call.Value
			m := v.Type().Underlying().(*types.Signature)
			s.passFuncParamTaint(m, inst)
		} else {
			// interface
			m := inst.Call.Method
			s.passInvokeTaint(m, inst)
		}
	case *ssa.Extract:
		// caller can be a Extract instruction
		if inst.Call.Method == nil {
			// if it is a function, its signature information is in inst.Call.Value
			m := v.Type().Underlying().(*types.Signature)
			s.passFuncParamTaint(m, inst)
		} else {
			// interface
			m := inst.Call.Method
			s.passInvokeTaint(m, inst)
		}
	case *ssa.Parameter:
		// caller can be a parameter
		if inst.Call.Method == nil {
			// if it is a function, its signature information is in inst.Call.Value
			m := v.Type().Underlying().(*types.Signature)
			s.passFuncParamTaint(m, inst)
		} else {
			// interface
			m := inst.Call.Method
			s.passInvokeTaint(m, inst)
		}
	case *ssa.Builtin:
		// builtins
		b := v
		switch b.Name() {
		case "append":
			s.passAppendTaint(inst)
		case "copy":
			s.passCopyTaint(inst)
		case
			"recover",
			"complex",
			"len",
			"delete",
			"panic",
			"real",
			"imag",
			"close",
			"print",
			"println",
			"make",
			"cap",
			"ssa:wrapnilchk":
			(*s.outMap)[inst.Name()] = make(map[string]bool)
		}
	case *ssa.Function:
		// caller can be a known function
		// global function, global method and anonymous function in function itself
		f := v
		s.passCallTaint(f, inst)
	default:
		if inst.Call.Method != nil {
			// we consider is as a interface
			m := inst.Call.Method
			s.passInvokeTaint(m, inst)
		}
	}
}

// CaseChangeInterface accepts a ChangeInterface instruction
func (s *TaintSwitcher) CaseChangeInterface(inst *ssa.ChangeInterface) {
	newTaint := make(map[string]bool)
	if _oldTaint, ok := (*s.outMap)[inst.X.Name()]; ok {
		// we drop *ssa.Global, *ssa.FreeVar and *ssa.Const
		oldTaint := _oldTaint.(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	(*s.outMap)[inst.Name()] = newTaint
}

// CaseChangeType accepts a ChangeType instruction
func (s *TaintSwitcher) CaseChangeType(inst *ssa.ChangeType) {
	newTaint := make(map[string]bool)
	if _oldTaint, ok := (*s.outMap)[inst.X.Name()]; ok {
		// we drop *ssa.Global, *ssa.FreeVar and *ssa.Const
		oldTaint := _oldTaint.(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	(*s.outMap)[inst.Name()] = newTaint
}

// CaseConvert accepts a Convert instruction
func (s *TaintSwitcher) CaseConvert(inst *ssa.Convert) {
	newTaint := make(map[string]bool)
	if _oldTaint, ok := (*s.outMap)[inst.X.Name()]; ok {
		// skip *ssa.Global, *ssa.FreeVar and *ssa.Const
		oldTaint := _oldTaint.(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	(*s.outMap)[inst.Name()] = newTaint
}

// CaseExtract accepts a Extract instruction
func (s *TaintSwitcher) CaseExtract(inst *ssa.Extract) {
	newTaint := make(map[string]bool)
	// mark the variables as "inst.Tuple.Name().i"
	// e.g. t1.0, t3.2
	oldTaint := (*s.outMap)[inst.Tuple.Name()+"."+strconv.Itoa(inst.Index)].(map[string]bool)
	for k := range oldTaint {
		newTaint[k] = true
	}
	(*s.outMap)[inst.Name()] = newTaint
}

// CaseField accepts a Field instruction
func (s *TaintSwitcher) CaseField(inst *ssa.Field) {
	newTaint := make(map[string]bool)
	if _, ok := (inst.X).(*ssa.Global); ok {
		// skip *ssa.Global
		(*s.outMap)[inst.Name()] = newTaint
	} else if _, ok := (inst.X).(*ssa.FreeVar); ok {
		// skip *ssa.FreeVar
		(*s.outMap)[inst.Name()] = newTaint
	} else {
		oldTaint := (*s.outMap)[inst.X.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
		(*s.outMap)[inst.Name()] = newTaint
	}
}

// CaseFieldAddr accepts a FieldAddr instruction
func (s *TaintSwitcher) CaseFieldAddr(inst *ssa.FieldAddr) {
	newTaint := make(map[string]bool)
	if _, ok := (inst.X).(*ssa.Global); ok {
		// skip *ssa.Global
		(*s.outMap)[inst.Name()] = newTaint
	} else if _, ok := (inst.X).(*ssa.FreeVar); ok {
		// skip *ssa.FreeVar
		(*s.outMap)[inst.Name()] = newTaint
	} else {
		oldTaint := (*s.outMap)[inst.X.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
		(*s.outMap)[inst.Name()] = newTaint
	}
}

// CaseIndex accepts an Index instruction
func (s *TaintSwitcher) CaseIndex(inst *ssa.Index) {
	newTaint := make(map[string]bool)
	if _, ok := (inst.X).(*ssa.Global); ok {
		// skip *ssa.Global
		(*s.outMap)[inst.Name()] = newTaint
	} else if _, ok := (inst.X).(*ssa.FreeVar); ok {
		// skip *ssa.FreeVar
		(*s.outMap)[inst.Name()] = newTaint
	} else {
		oldTaint := (*s.outMap)[inst.X.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
		(*s.outMap)[inst.Name()] = newTaint
	}
}

// CaseIndexAddr accepts an IndexAddr instruction
func (s *TaintSwitcher) CaseIndexAddr(inst *ssa.IndexAddr) {
	newTaint := make(map[string]bool)
	if _, ok := (inst.X).(*ssa.Global); ok {
		// skip *ssa.Global
		(*s.outMap)[inst.Name()] = newTaint
	} else if _, ok := (inst.X).(*ssa.FreeVar); ok {
		// skip *ssa.FreeVar
		(*s.outMap)[inst.Name()] = newTaint
	} else {
		oldTaint := (*s.outMap)[inst.X.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
		(*s.outMap)[inst.Name()] = newTaint
	}
}

// CaseLookup accepts a Lookup instruction
func (s *TaintSwitcher) CaseLookup(inst *ssa.Lookup) {
	newTaint := make(map[string]bool)
	// pass taint in index
	switch k := (inst.Index).(type) {
	case *ssa.Parameter:
		newTaint[k.Name()] = true
	case *ssa.Alloc,
		*ssa.BinOp,
		*ssa.Call,
		*ssa.ChangeType,
		*ssa.ChangeInterface,
		*ssa.Convert,
		*ssa.Extract,
		*ssa.Field,
		*ssa.FieldAddr,
		*ssa.Index,
		*ssa.IndexAddr,
		*ssa.Lookup,
		*ssa.MakeChan,
		*ssa.MakeInterface,
		*ssa.MakeMap,
		*ssa.MakeSlice,
		*ssa.Next,
		*ssa.Range,
		*ssa.Slice,
		*ssa.TypeAssert,
		*ssa.UnOp,
		*ssa.Phi:
		oldTaint := (*s.outMap)[k.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	// pass taint in map
	switch v := (inst.X).(type) {
	case *ssa.Parameter:
		newTaint[v.Name()] = true
	case *ssa.Alloc,
		*ssa.BinOp,
		*ssa.Call,
		*ssa.ChangeType,
		*ssa.ChangeInterface,
		*ssa.Convert,
		*ssa.Extract,
		*ssa.Field,
		*ssa.FieldAddr,
		*ssa.Index,
		*ssa.IndexAddr,
		*ssa.Lookup,
		*ssa.MakeChan,
		*ssa.MakeInterface,
		*ssa.MakeMap,
		*ssa.MakeSlice,
		*ssa.Next,
		*ssa.Range,
		*ssa.Slice,
		*ssa.TypeAssert,
		*ssa.UnOp,
		*ssa.Phi:
		oldTaint := (*s.outMap)[v.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	if inst.CommaOk {
		// if needs an ok, mark two variables, and the first one inherits taint
		(*s.outMap)[inst.Name()+".0"] = newTaint
		(*s.outMap)[inst.Name()+".1"] = make(map[string]bool)
	} else {
		(*s.outMap)[inst.Name()] = newTaint
	}
}

// CaseMakeClosure accepts a MakeClosure instruction
func (s *TaintSwitcher) CaseMakeClosure(inst *ssa.MakeClosure) {
	(*s.outMap)[inst.Name()] = make(map[string]bool)
}

// CaseMakeChan accepts a MakeChan instruction
func (s *TaintSwitcher) CaseMakeChan(inst *ssa.MakeChan) {
	(*s.outMap)[inst.Name()] = make(map[string]bool)
}

// CaseMakeInterface accepts a MakeInterface instruction
func (s *TaintSwitcher) CaseMakeInterface(inst *ssa.MakeInterface) {
	newTaint := make(map[string]bool)
	if _, ok := (inst.X).(*ssa.Const); ok {
		(*s.outMap)[inst.Name()] = newTaint
	} else {
		// exclude close$thunk
		_, ok := (*s.outMap)[inst.X.Name()]
		if ok {
			oldTaint := (*s.outMap)[inst.X.Name()].(map[string]bool)
			for k := range oldTaint {
				newTaint[k] = true
			}
		}
		(*s.outMap)[inst.Name()] = newTaint
	}
}

// CaseMakeMap accepts a MakeMap instruction
func (s *TaintSwitcher) CaseMakeMap(inst *ssa.MakeMap) {
	(*s.outMap)[inst.Name()] = make(map[string]bool)
}

// CaseMakeSlice accepts a MakeSlice instruction
func (s *TaintSwitcher) CaseMakeSlice(inst *ssa.MakeSlice) {
	(*s.outMap)[inst.Name()] = make(map[string]bool)
}

// CaseNext accepts a Next instruction
func (s *TaintSwitcher) CaseNext(inst *ssa.Next) {
	newTaint1 := make(map[string]bool)
	newTaint2 := make(map[string]bool)
	oldTaint := (*s.outMap)[inst.Iter.Name()].(map[string]bool)
	for k := range oldTaint {
		newTaint1[k] = true
		newTaint2[k] = true
	}
	// mark three variables, and the first one inherits taint
	(*s.outMap)[inst.Name()+".0"] = make(map[string]bool)
	(*s.outMap)[inst.Name()+".1"] = newTaint1
	(*s.outMap)[inst.Name()+".2"] = newTaint2
}

// CaseMapUpdate accepts a MapUpdate instruction
func (s *TaintSwitcher) CaseMapUpdate(inst *ssa.MapUpdate) {
	newTaint := make(map[string]bool)
	// pass taint in key
	switch k := (inst.Key).(type) {
	case *ssa.Parameter:
		newTaint[k.Name()] = true
	case *ssa.Alloc,
		*ssa.BinOp,
		*ssa.Call,
		*ssa.ChangeType,
		*ssa.ChangeInterface,
		*ssa.Convert,
		*ssa.Extract,
		*ssa.Field,
		*ssa.FieldAddr,
		*ssa.Index,
		*ssa.IndexAddr,
		*ssa.Lookup,
		*ssa.MakeChan,
		*ssa.MakeInterface,
		*ssa.MakeMap,
		*ssa.MakeSlice,
		*ssa.Next,
		*ssa.Range,
		*ssa.Slice,
		*ssa.TypeAssert,
		*ssa.UnOp,
		*ssa.Phi:
		oldTaint := (*s.outMap)[k.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	// pass taint in value
	switch v := (inst.Value).(type) {
	case *ssa.Parameter:
		newTaint[v.Name()] = true
	case *ssa.Alloc,
		*ssa.BinOp,
		*ssa.Call,
		*ssa.ChangeType,
		*ssa.ChangeInterface,
		*ssa.Convert,
		*ssa.Extract,
		*ssa.Field,
		*ssa.FieldAddr,
		*ssa.Index,
		*ssa.IndexAddr,
		*ssa.Lookup,
		*ssa.MakeChan,
		*ssa.MakeInterface,
		*ssa.MakeMap,
		*ssa.MakeSlice,
		*ssa.Next,
		*ssa.Range,
		*ssa.Slice,
		*ssa.TypeAssert,
		*ssa.UnOp,
		*ssa.Phi:
		oldTaint := (*s.outMap)[v.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	// pass taint in map
	oldTaint2 := (*s.outMap)[inst.Map.Name()].(map[string]bool)
	for k := range oldTaint2 {
		newTaint[k] = true
	}
	(*s.outMap)[inst.Map.Name()] = newTaint
}

// CasePhi accepts a Phi instruction
func (s *TaintSwitcher) CasePhi(inst *ssa.Phi) {
	newTaint := make(map[string]bool)
	for _, _v := range inst.Edges {
		switch v := _v.(type) {
		case *ssa.Parameter:
			oldTaint := (*s.outMap)[v.Name()].(map[string]bool)
			for k := range oldTaint {
				newTaint[k] = true
			}
		case *ssa.Alloc,
			*ssa.BinOp,
			*ssa.Call,
			*ssa.ChangeType,
			*ssa.ChangeInterface,
			*ssa.Convert,
			*ssa.Extract,
			*ssa.Field,
			*ssa.FieldAddr,
			*ssa.Index,
			*ssa.IndexAddr,
			*ssa.Lookup,
			*ssa.MakeChan,
			*ssa.MakeInterface,
			*ssa.MakeMap,
			*ssa.MakeSlice,
			*ssa.Next,
			*ssa.Range,
			*ssa.Slice,
			*ssa.TypeAssert,
			*ssa.UnOp,
			*ssa.Phi:
			// Phi is the gather of instructions
			// It may visit uninitialized register, so add an if
			_oldTaint, ok := (*s.outMap)[v.Name()]
			if !ok {
				continue
			}
			oldTaint := _oldTaint.(map[string]bool)
			for k := range oldTaint {
				newTaint[k] = true
			}
		}
	}
	(*s.outMap)[inst.Name()] = newTaint
}

// CaseRange accepts a Range instruction
func (s *TaintSwitcher) CaseRange(inst *ssa.Range) {
	newTaint := make(map[string]bool)
	if _oldTaint, ok := (*s.outMap)[inst.X.Name()]; ok {
		oldTaint := _oldTaint.(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	(*s.outMap)[inst.Name()] = newTaint
}

// CaseReturn accepts a Return instruction
func (s *TaintSwitcher) CaseReturn(inst *ssa.Return) {
	f := s.taintAnalysis.Graph.Func
	if f.Signature.Recv() != nil {
		// if the function has a receiver
		recv := f.Params[0].Name()
		for k := range (*s.outMap)[recv].(map[string]bool) {
			// merge receiver's taint into passthrough
			s.taintAnalysis.passThrough[0][k] = true
		}
		for i := 0; i < len(inst.Results); i++ {
			result := inst.Results[i].Name()
			// skip *ssa.Global, *ssa.FreeVar and *ssa.Const
			_, ok := (*s.outMap)[result]
			if ok {
				for k := range (*s.outMap)[result].(map[string]bool) {
					// merge other results' taint
					s.taintAnalysis.passThrough[i+1][k] = true
				}
			}
		}
	} else {
		for i := 0; i < len(inst.Results); i++ {
			result := inst.Results[i].Name()
			// skip *ssa.Global, *ssa.FreeVar and *ssa.Const
			_, ok := (*s.outMap)[result]
			if ok {
				for k := range (*s.outMap)[result].(map[string]bool) {
					// merge other results' taint
					s.taintAnalysis.passThrough[i][k] = true
				}
			}
		}
	}
}

// CaseSend accepts a Send instruction
func (s *TaintSwitcher) CaseSend(inst *ssa.Send) {
	newTaint := make(map[string]bool)
	switch x := (inst.X).(type) {
	case *ssa.Parameter:
		newTaint[x.Name()] = true
	case
		*ssa.Alloc,
		*ssa.BinOp,
		*ssa.Call,
		*ssa.ChangeType,
		*ssa.ChangeInterface,
		*ssa.Convert,
		*ssa.Extract,
		*ssa.Field,
		*ssa.FieldAddr,
		*ssa.Index,
		*ssa.IndexAddr,
		*ssa.Lookup,
		*ssa.MakeChan,
		*ssa.MakeInterface,
		*ssa.MakeMap,
		*ssa.MakeSlice,
		*ssa.Next,
		*ssa.Range,
		*ssa.Slice,
		*ssa.TypeAssert,
		*ssa.UnOp,
		*ssa.Phi:
		oldTaint := (*s.outMap)[x.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	(*s.outMap)[inst.Chan.Name()] = newTaint
}

// CaseSelect accepts a Select instruction
func (s *TaintSwitcher) CaseSelect(inst *ssa.Select) {
	// mark variables as "inst.Name().i"
	// e.g. t2.0, t2.1
	newTaint := make(map[string]bool)
	(*s.outMap)[inst.Name()+".0"] = newTaint
	newTaint1 := make(map[string]bool)
	(*s.outMap)[inst.Name()+".1"] = newTaint1
	for k := range inst.States {
		newTaint := make(map[string]bool)
		(*s.outMap)[inst.Name()+"."+strconv.Itoa(k+2)] = newTaint
	}
}

// CaseSlice accepts a Slice instruction
func (s *TaintSwitcher) CaseSlice(inst *ssa.Slice) {
	newTaint := make(map[string]bool)
	// pass underlying array's taint
	if _oldTaint, ok := (*s.outMap)[inst.X.Name()]; ok {
		oldTaint := _oldTaint.(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	(*s.outMap)[inst.Name()] = newTaint
}

// CaseStore accepts a Store instruction
func (s *TaintSwitcher) CaseStore(inst *ssa.Store) {
	newTaint := make(map[string]bool)
	// Store needs to visit pointer
	_oldTaint, ok := (*s.outMap)[inst.Addr.Name()]
	if ok {
		oldTaint := _oldTaint.(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	switch v := inst.Val.(type) {
	case *ssa.Parameter:
		newTaint[v.Name()] = true
	case *ssa.Alloc,
		*ssa.BinOp,
		*ssa.Call,
		*ssa.ChangeType,
		*ssa.ChangeInterface,
		*ssa.Convert,
		*ssa.Extract,
		*ssa.Field,
		*ssa.FieldAddr,
		*ssa.Index,
		*ssa.IndexAddr,
		*ssa.Lookup,
		*ssa.MakeChan,
		*ssa.MakeInterface,
		*ssa.MakeMap,
		*ssa.MakeSlice,
		*ssa.Next,
		*ssa.Range,
		*ssa.Slice,
		*ssa.TypeAssert,
		*ssa.UnOp,
		*ssa.Phi:
		oldTaint := (*s.outMap)[v.Name()].(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	(*s.outMap)[inst.Addr.Name()] = newTaint
	// if inst.Addr points to struct or slice, update further
	newTaint2 := make(map[string]bool)
	switch addr := (inst.Addr).(type) {
	case *ssa.Global:
		// save global anonymous function to initMap
		if f, ok := (inst.Val).(*ssa.Function); ok {
			(*s.taintAnalysis.initMap)[addr.String()] = f
		}
	case *ssa.FieldAddr:
		if _, ok := (addr.X).(*ssa.Global); ok {
			// skip *ssa.Global
			(*s.outMap)[addr.X.Name()] = newTaint2
		} else if _, ok := (addr.X).(*ssa.FreeVar); ok {
			// skip *ssa.FreeVar
			(*s.outMap)[addr.X.Name()] = newTaint2
		} else {
			oldTaint2 := (*s.outMap)[addr.X.Name()].(map[string]bool)
			for k := range oldTaint2 {
				newTaint2[k] = true
			}
			for k := range newTaint {
				newTaint2[k] = true
			}
			(*s.outMap)[addr.X.Name()] = newTaint2
			if fieldAddr, ok := addr.X.(*ssa.FieldAddr); ok {
				// if inst.Addr.X is still a *ssa.FieldAddr, update further
				newTaint3 := make(map[string]bool)
				if _oldTaint, ok := (*s.outMap)[fieldAddr.X.Name()]; ok {
					oldTaint3 := _oldTaint.(map[string]bool)
					for k := range oldTaint3 {
						newTaint3[k] = true
					}
					for k := range newTaint {
						newTaint3[k] = true
					}
					(*s.outMap)[fieldAddr.X.Name()] = newTaint3
				}
			}
		}
	case *ssa.IndexAddr:
		if _, ok := (addr.X).(*ssa.Global); ok {
			// skip *ssa.Global
			(*s.outMap)[addr.X.Name()] = newTaint2
		} else if _, ok := (addr.X).(*ssa.FreeVar); ok {
			// skip *ssa.FreeVar
			(*s.outMap)[addr.X.Name()] = newTaint2
		} else {
			oldTaint2 := (*s.outMap)[addr.X.Name()].(map[string]bool)
			for k := range oldTaint2 {
				newTaint2[k] = true
			}
			for k := range newTaint {
				newTaint2[k] = true
			}
			(*s.outMap)[addr.X.Name()] = newTaint2
			// if inst.Addr.X is a *ssa.Slice, update underlying array
			slice, ok := addr.X.(*ssa.Slice)
			newTaint3 := make(map[string]bool)
			if ok {
				oldTaint3 := (*s.outMap)[slice.X.Name()].(map[string]bool)
				for k := range oldTaint3 {
					newTaint3[k] = true
				}
				for k := range newTaint {
					newTaint3[k] = true
				}
				(*s.outMap)[slice.X.Name()] = newTaint3
			}
		}
	}
}

// CaseTypeAssert accepts a TypeAssert instruction
func (s *TaintSwitcher) CaseTypeAssert(inst *ssa.TypeAssert) {
	newTaint := make(map[string]bool)
	if _oldTaint, ok := (*s.outMap)[inst.X.Name()]; ok {
		// skip *ssa.Global, *ssa.FreeVar and *ssa.Const
		oldTaint := _oldTaint.(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	if inst.CommaOk {
		// if needs an ok, mark two variables, and the first one inherits taint
		(*s.outMap)[inst.Name()+".0"] = newTaint
		(*s.outMap)[inst.Name()+".1"] = make(map[string]bool)
	} else {
		(*s.outMap)[inst.Name()] = newTaint
	}
}

// CaseUnOp accepts a UnOp instruction
func (s *TaintSwitcher) CaseUnOp(inst *ssa.UnOp) {
	newTaint := make(map[string]bool)
	switch x := (inst.X).(type) {
	case *ssa.Parameter:
		if inst.Op == token.ARROW && inst.CommaOk {
			// if needs an ok, mark two variables, and the first one inherits taint
			newTaint[x.Name()] = true
			(*s.outMap)[inst.Name()+".0"] = newTaint
			(*s.outMap)[inst.Name()+".1"] = make(map[string]bool)
		} else {
			newTaint[x.Name()] = true
			(*s.outMap)[inst.Name()] = newTaint
		}
	case *ssa.FreeVar,
		*ssa.Global:
		if inst.Op == token.ARROW && inst.CommaOk {
			// if needs an ok, mark two variables, and the first one inherits taint
			// although here is no taint ^^ now
			(*s.outMap)[inst.Name()+".0"] = newTaint
			(*s.outMap)[inst.Name()+".1"] = make(map[string]bool)
		} else {
			(*s.outMap)[inst.Name()] = newTaint
		}
	case *ssa.Alloc,
		*ssa.BinOp,
		*ssa.Call,
		*ssa.ChangeType,
		*ssa.ChangeInterface,
		*ssa.Convert,
		*ssa.Extract,
		*ssa.Field,
		*ssa.FieldAddr,
		*ssa.Index,
		*ssa.IndexAddr,
		*ssa.Lookup,
		*ssa.MakeChan,
		*ssa.MakeInterface,
		*ssa.MakeMap,
		*ssa.MakeSlice,
		*ssa.Next,
		*ssa.Range,
		*ssa.Slice,
		*ssa.TypeAssert,
		*ssa.UnOp,
		*ssa.Phi:
		if inst.Op == token.ARROW && inst.CommaOk {
			// if needs an ok, mark two variables, and the first one inherits taint
			oldTaint := (*s.outMap)[x.Name()].(map[string]bool)
			for k := range oldTaint {
				newTaint[k] = true
			}
			(*s.outMap)[inst.Name()+".0"] = newTaint
			(*s.outMap)[inst.Name()+".1"] = make(map[string]bool)
		} else {
			oldTaint := (*s.outMap)[x.Name()].(map[string]bool)
			for k := range oldTaint {
				newTaint[k] = true
			}
			(*s.outMap)[inst.Name()] = newTaint
		}
	}
}

// passCallTaint passes taint by *ssa.Function and a call
func (s *TaintSwitcher) passCallTaint(f *ssa.Function, inst *ssa.Call) {
	container := s.taintAnalysis.passThroughContainer
	c := s.taintAnalysis.config
	_, ok := (*container)[f.String()]
	if !ok {
		if needNull(f, c) {
			// function is loaded from C file and has no body
			m, ok := f.Object().(*types.Func)
			if ok {
				s.passNullTaint(m, inst)
			}
			return
		}
		// if we can saved it, load it now
		Run(f, c)
	}

	passThrough := (*container)[f.String()]
	n := len(passThrough)
	// for every results
	for i := 0; i < n; i++ {
		newTaint := make(map[string]bool)
		// for every parameter index in passthrough, collect arg's taint
		for _, p := range passThrough[i] {
			switch arg := (inst.Call.Args[p]).(type) {
			case *ssa.Parameter:
				newTaint[arg.Name()] = true
			case *ssa.Alloc,
				*ssa.BinOp,
				*ssa.Call,
				*ssa.ChangeType,
				*ssa.ChangeInterface,
				*ssa.Convert,
				*ssa.Extract,
				*ssa.Field,
				*ssa.FieldAddr,
				*ssa.Index,
				*ssa.IndexAddr,
				*ssa.Lookup,
				*ssa.MakeChan,
				*ssa.MakeInterface,
				*ssa.MakeMap,
				*ssa.MakeSlice,
				*ssa.Next,
				*ssa.Range,
				*ssa.Slice,
				*ssa.TypeAssert,
				*ssa.UnOp,
				*ssa.Phi:
				if _oldTaint, ok := (*s.outMap)[arg.Name()]; ok {
					oldTaint := _oldTaint.(map[string]bool)
					for k := range oldTaint {
						newTaint[k] = true
					}
				}
			}
		}
		if f.Signature.Recv() != nil {
			// if the function has a receiver
			if i == 0 {
				// update receiver's taint
				// the receiver may be a pointer, so update further by the pointer
				(*s.outMap)[inst.Call.Args[0].Name()] = newTaint
				if op, ok := (inst.Call.Args[0]).(*ssa.UnOp); ok {
					s.passPointTaint(newTaint, op.X)
				} else {
					s.passPointTaint(newTaint, inst.Call.Args[0])
				}
			} else {
				if n == 2 {
					// if the function has one result
					(*s.outMap)[inst.Name()] = newTaint
				} else {
					// else mark the variables as "inst.Name().X"
					// e.g. t0.1, t0.2
					(*s.outMap)[inst.Name()+"."+strconv.Itoa(i-1)] = newTaint
				}
			}
		} else {
			// if the function has no receiver
			if n == 1 {
				// if the function has one result
				(*s.outMap)[inst.Name()] = newTaint
			} else {
				// else mark the variables as "inst.Name().X"
				// e.g. t0.1, t0.2
				(*s.outMap)[inst.Name()+"."+strconv.Itoa(i)] = newTaint
			}
		}
	}
}

// passPointTaint passes taint by pointer
func (s *TaintSwitcher) passPointTaint(newTaint map[string]bool, pointer ssa.Value) {
	switch inst := (pointer).(type) {
	case *ssa.FieldAddr:
		newTaint2 := make(map[string]bool)
		if _, ok := inst.X.(*ssa.Global); ok {
			(*s.outMap)[inst.X.Name()] = newTaint2
		} else if _, ok := inst.X.(*ssa.FreeVar); ok {
			(*s.outMap)[inst.X.Name()] = newTaint2
		} else {
			if _oldTaint, ok := (*s.outMap)[inst.X.Name()]; ok {
				oldTaint := _oldTaint.(map[string]bool)
				for k := range oldTaint {
					newTaint2[k] = true
				}
			}
			for k := range newTaint {
				newTaint2[k] = true
			}
			(*s.outMap)[inst.X.Name()] = newTaint2
		}
	case *ssa.IndexAddr:
		if _, ok := (inst.X).(*ssa.Global); ok {
			// do nothing
		} else if _, ok := (inst.X).(*ssa.FreeVar); ok {
			// do nothing
		} else {
			oldTaint := (*s.outMap)[inst.X.Name()].(map[string]bool)
			newTaint2 := make(map[string]bool)
			for k := range oldTaint {
				newTaint2[k] = true
			}
			for k := range newTaint {
				newTaint2[k] = true
			}
			(*s.outMap)[inst.X.Name()] = newTaint2
			// if it is a *ssa.Slice, update underlying array
			slice, ok := inst.X.(*ssa.Slice)
			if ok {
				newTaint3 := make(map[string]bool)
				oldTaint3 := (*s.outMap)[slice.X.Name()].(map[string]bool)
				for k := range oldTaint3 {
					newTaint3[k] = true
				}
				for k := range newTaint {
					newTaint3[k] = true
				}
				(*s.outMap)[slice.X.Name()] = newTaint3
			}
		}
	}
}

// passAppendTaint passes taint by append
func (s *TaintSwitcher) passAppendTaint(inst *ssa.Call) {
	newTaint := make(map[string]bool)
	n := len(inst.Call.Args)
	for i := 0; i < n; i++ {
		// collect taint in slices
		switch arg := (inst.Call.Args[i]).(type) {
		case
			// need *ssa.UnOp，may be more other types
			// e.g. path/path.go Join
			// buf = append(buf, e...)
			*ssa.Parameter,
			*ssa.Phi,
			*ssa.Slice,
			*ssa.UnOp:
			oldTaint := (*s.outMap)[arg.Name()].(map[string]bool)
			for k := range oldTaint {
				newTaint[k] = true
			}
		}
	}
	(*s.outMap)[inst.Name()] = newTaint
	for i := 0; i < n; i++ {
		// pass taint to every slice
		newTaint2 := make(map[string]bool)
		switch arg := (inst.Call.Args[i]).(type) {
		case
			*ssa.Parameter,
			*ssa.Phi,
			*ssa.Slice,
			*ssa.UnOp:
			for k := range newTaint {
				newTaint2[k] = true
			}
			(*s.outMap)[arg.Name()] = newTaint2
		}
	}
}

// passInvokeTaint passes taint by *types.Func
// actually, only interfaces use this
func (s *TaintSwitcher) passInvokeTaint(f *types.Func, inst *ssa.Call) {
	interfaceHierarchy := s.taintAnalysis.interfaceHierarchy
	tiface := inst.Call.Value.Type().Underlying().(*types.Interface)
	methods := interfaceHierarchy.LookupMethods(tiface, f)
	if len(methods) != 0 {
		s.passMethodTaint(methods[0], inst)
	} else {
		s.passNullTaint(f, inst)
	}
}

// passMethodTaint passes taint by *ssa.Function and an invoke
func (s *TaintSwitcher) passMethodTaint(f *ssa.Function, inst *ssa.Call) {
	container := s.taintAnalysis.passThroughContainer
	c := s.taintAnalysis.config
	_, ok := (*container)[f.String()]
	if !ok {
		if needNull(f, c) {
			// function is loaded from C file and has no body
			m, ok := f.Object().(*types.Func)
			if ok {
				s.passNullTaint(m, inst)
			}
			return
		}
		// if we can saved it, load it now
		Run(f, c)
	}

	passThrough := (*container)[f.String()]
	n := len(passThrough)
	for i := 0; i < n; i++ {
		newTaint := make(map[string]bool)
		// for every parameter index in passthrough, collect arg's taint
		for _, p := range passThrough[i] {
			if p == 0 {
				// the first arg is inst.Call.Value
				switch arg := (inst.Call.Value).(type) {
				case *ssa.Parameter:
					newTaint[arg.Name()] = true
				case *ssa.Alloc,
					*ssa.BinOp,
					*ssa.Call,
					*ssa.ChangeType,
					*ssa.ChangeInterface,
					*ssa.Convert,
					*ssa.Extract,
					*ssa.Field,
					*ssa.FieldAddr,
					*ssa.Index,
					*ssa.IndexAddr,
					*ssa.Lookup,
					*ssa.MakeChan,
					*ssa.MakeInterface,
					*ssa.MakeMap,
					*ssa.MakeSlice,
					*ssa.Next,
					*ssa.Range,
					*ssa.Slice,
					*ssa.TypeAssert,
					*ssa.UnOp,
					*ssa.Phi:
					if _oldTaint, ok := (*s.outMap)[arg.Name()]; ok {
						oldTaint := _oldTaint.(map[string]bool)
						for k := range oldTaint {
							newTaint[k] = true
						}
					}
				}
			} else {
				// other args are in inst.Call.Args
				switch arg := (inst.Call.Args[p-1]).(type) {
				case *ssa.Parameter:
					newTaint[arg.Name()] = true
				case *ssa.Alloc,
					*ssa.BinOp,
					*ssa.Call,
					*ssa.ChangeType,
					*ssa.ChangeInterface,
					*ssa.Convert,
					*ssa.Extract,
					*ssa.Field,
					*ssa.FieldAddr,
					*ssa.Index,
					*ssa.IndexAddr,
					*ssa.Lookup,
					*ssa.MakeChan,
					*ssa.MakeInterface,
					*ssa.MakeMap,
					*ssa.MakeSlice,
					*ssa.Next,
					*ssa.Range,
					*ssa.Slice,
					*ssa.TypeAssert,
					*ssa.UnOp,
					*ssa.Phi:
					if _oldTaint, ok := (*s.outMap)[arg.Name()]; ok {
						oldTaint := _oldTaint.(map[string]bool)
						for k := range oldTaint {
							newTaint[k] = true
						}
					}
				}
			}
		}
		if i == 0 {
			// update receiver's taint
			// the receiver may be a pointer, so update further by the pointer
			(*s.outMap)[inst.Call.Value.Name()] = newTaint
			if op, ok := (inst.Call.Value).(*ssa.UnOp); ok {
				s.passPointTaint(newTaint, op.X)
			} else {
				s.passPointTaint(newTaint, inst.Call.Value)
			}
		} else {
			if n == 2 {
				// if the function has one result
				(*s.outMap)[inst.Name()] = newTaint
			} else {
				// else mark the variables as "inst.Name().X"
				// e.g. t0.1, t0.2
				(*s.outMap)[inst.Name()+"."+strconv.Itoa(i-1)] = newTaint
			}
		}
	}
}

// passNullTaint passes taint when we can't know a declared function's body or have to inhibit recursive
// actually no taint will be passed
func (s *TaintSwitcher) passNullTaint(f *types.Func, inst *ssa.Call) {
	container := s.taintAnalysis.passThroughContainer
	signature, ok := f.Type().(*types.Signature)
	if ok {
		passThrough := make([][]int, 0)
		if signature.Recv() != nil {
			passThrough = append(passThrough, make([]int, 0))
		}
		n := signature.Results().Len()
		for i := 0; i < n; i++ {
			passThrough = append(passThrough, make([]int, 0))
		}
		(*container)[f.String()] = passThrough
		n = len(passThrough)
		for i := 0; i < n; i++ {
			newTaint := make(map[string]bool)
			if signature.Recv() != nil {
				if i == 0 {
				} else {
					if n == 2 {
						(*s.outMap)[inst.Name()] = newTaint
					} else {
						(*s.outMap)[inst.Name()+"."+strconv.Itoa(i-1)] = newTaint
					}
				}
			} else {
				if n == 1 {
					(*s.outMap)[inst.Name()] = newTaint
				} else {
					(*s.outMap)[inst.Name()+"."+strconv.Itoa(i)] = newTaint
				}
			}
		}
		newTaint := make(map[string]bool)
		(*s.outMap)[inst.Name()] = newTaint
	}
}

// passFuncParamTaint passes taint by *types.Signature
// actually, only functions without body use this
func (s *TaintSwitcher) passFuncParamTaint(signature *types.Signature, inst *ssa.Call) {
	passThrough := make([][]int, 0)
	n := signature.Results().Len()
	for i := 0; i < n; i++ {
		passThrough = append(passThrough, make([]int, 0))
	}
	n = len(passThrough)
	for i := 0; i < n; i++ {
		newTaint := make(map[string]bool)
		if n != 1 {
			(*s.outMap)[inst.Name()+"."+strconv.Itoa(i)] = newTaint
		}
	}
	newTaint := make(map[string]bool)
	(*s.outMap)[inst.Name()] = newTaint
}

// passCopyTaint pass taint by copy
func (s *TaintSwitcher) passCopyTaint(inst *ssa.Call) {
	oldTaint2 := (*s.outMap)[inst.Call.Args[0].Name()].(map[string]bool)
	newTaint := make(map[string]bool)
	if _oldTaint, ok := (*s.outMap)[inst.Call.Args[1].Name()]; ok {
		oldTaint := _oldTaint.(map[string]bool)
		for k := range oldTaint {
			newTaint[k] = true
		}
	}
	for k := range oldTaint2 {
		newTaint[k] = true
	}
	(*s.outMap)[inst.Call.Args[0].Name()] = newTaint
	newTaint2 := make(map[string]bool)
	(*s.outMap)[inst.Name()] = newTaint2
}

package switcher

import "golang.org/x/tools/go/ssa"

// Switcher represents a ssa instruction switcher
type Switcher interface {
	CaseAlloc(inst *ssa.Alloc)
	CasePhi(inst *ssa.Phi)
	CaseCall(inst *ssa.Call)
	CaseBinOp(inst *ssa.BinOp)
	CaseUnOp(inst *ssa.UnOp)
	CaseChangeType(inst *ssa.ChangeType)
	CaseConvert(inst *ssa.Convert)
	CaseChangeInterface(inst *ssa.ChangeInterface)
	CaseSliceToArrayPointer(inst *ssa.SliceToArrayPointer)
	CaseMakeInterface(inst *ssa.MakeInterface)
	CaseMakeClosure(inst *ssa.MakeClosure)
	CaseMakeMap(inst *ssa.MakeMap)
	CaseMakeChan(inst *ssa.MakeChan)
	CaseMakeSlice(inst *ssa.MakeSlice)
	CaseSlice(inst *ssa.Slice)
	CaseFieldAddr(inst *ssa.FieldAddr)
	CaseField(inst *ssa.Field)
	CaseIndexAddr(inst *ssa.IndexAddr)
	CaseIndex(inst *ssa.Index)
	CaseLookup(inst *ssa.Lookup)
	CaseSelect(inst *ssa.Select)
	CaseRange(inst *ssa.Range)
	CaseNext(inst *ssa.Next)
	CaseTypeAssert(inst *ssa.TypeAssert)
	CaseExtract(inst *ssa.Extract)
	CaseJump(inst *ssa.Jump)
	CaseIf(inst *ssa.If)
	CaseReturn(inst *ssa.Return)
	CaseRunDefers(inst *ssa.RunDefers)
	CasePanic(inst *ssa.Panic)
	CaseGo(inst *ssa.Go)
	CaseDefer(inst *ssa.Defer)
	CaseSend(inst *ssa.Send)
	CaseStore(inst *ssa.Store)
	CaseMapUpdate(inst *ssa.MapUpdate)
	CaseDebugRef(inst *ssa.DebugRef)
}

// Apply call specific method based on type of the instruction
func Apply(s Switcher, _inst ssa.Instruction) {
	switch inst := _inst.(type) {
	case *ssa.Alloc:
		s.CaseAlloc(inst)
	case *ssa.Phi:
		s.CasePhi(inst)
	case *ssa.Call:
		s.CaseCall(inst)
	case *ssa.BinOp:
		s.CaseBinOp(inst)
	case *ssa.UnOp:
		s.CaseUnOp(inst)
	case *ssa.ChangeType:
		s.CaseChangeType(inst)
	case *ssa.Convert:
		s.CaseConvert(inst)
	case *ssa.ChangeInterface:
		s.CaseChangeInterface(inst)
	case *ssa.SliceToArrayPointer:
		s.CaseSliceToArrayPointer(inst)
	case *ssa.MakeInterface:
		s.CaseMakeInterface(inst)
	case *ssa.MakeClosure:
		s.CaseMakeClosure(inst)
	case *ssa.MakeMap:
		s.CaseMakeMap(inst)
	case *ssa.MakeChan:
		s.CaseMakeChan(inst)
	case *ssa.MakeSlice:
		s.CaseMakeSlice(inst)
	case *ssa.Slice:
		s.CaseSlice(inst)
	case *ssa.FieldAddr:
		s.CaseFieldAddr(inst)
	case *ssa.Field:
		s.CaseField(inst)
	case *ssa.IndexAddr:
		s.CaseIndexAddr(inst)
	case *ssa.Index:
		s.CaseIndex(inst)
	case *ssa.Lookup:
		s.CaseLookup(inst)
	case *ssa.Select:
		s.CaseSelect(inst)
	case *ssa.Range:
		s.CaseRange(inst)
	case *ssa.Next:
		s.CaseNext(inst)
	case *ssa.TypeAssert:
		s.CaseTypeAssert(inst)
	case *ssa.Extract:
		s.CaseExtract(inst)
	case *ssa.Jump:
		s.CaseJump(inst)
	case *ssa.If:
		s.CaseIf(inst)
	case *ssa.Return:
		s.CaseReturn(inst)
	case *ssa.RunDefers:
		s.CaseRunDefers(inst)
	case *ssa.Panic:
		s.CasePanic(inst)
	case *ssa.Go:
		s.CaseGo(inst)
	case *ssa.Defer:
		s.CaseDefer(inst)
	case *ssa.Send:
		s.CaseSend(inst)
	case *ssa.Store:
		s.CaseStore(inst)
	case *ssa.MapUpdate:
		s.CaseMapUpdate(inst)
	case *ssa.DebugRef:
		s.CaseDebugRef(inst)
	}
}

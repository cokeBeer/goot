package switcher

import (
	"golang.org/x/tools/go/ssa"
)

// BaseSwitcher represents a base switcher implemention
type BaseSwitcher struct {
}

// CaseAlloc accepts an Alloc instruction
func (s *BaseSwitcher) CaseAlloc(inst *ssa.Alloc) {}

// CasePhi accepts a Phi instruction
func (s *BaseSwitcher) CasePhi(inst *ssa.Phi) {}

// CaseCall accepts a Call instruction
func (s *BaseSwitcher) CaseCall(inst *ssa.Call) {}

// CaseBinOp accepts a BinOp instruction
func (s *BaseSwitcher) CaseBinOp(inst *ssa.BinOp) {}

// CaseUnOp accepts a UnOp instruction
func (s *BaseSwitcher) CaseUnOp(inst *ssa.UnOp) {}

// CaseChangeType accepts a ChangeType instruction
func (s *BaseSwitcher) CaseChangeType(inst *ssa.ChangeType) {}

// CaseConvert accepts a Convert instruction
func (s *BaseSwitcher) CaseConvert(inst *ssa.Convert) {}

// CaseChangeInterface accepts a ChangeInterface instruction
func (s *BaseSwitcher) CaseChangeInterface(inst *ssa.ChangeInterface) {}

// CaseSliceToArrayPointer accepts a SliceToArrayPointer instruction
func (s *BaseSwitcher) CaseSliceToArrayPointer(inst *ssa.SliceToArrayPointer) {}

// CaseMakeInterface accepts a MakeInterface instruction
func (s *BaseSwitcher) CaseMakeInterface(inst *ssa.MakeInterface) {}

// CaseMakeClosure accepts a MakeMakeClosure instruction
func (s *BaseSwitcher) CaseMakeClosure(inst *ssa.MakeClosure) {}

// CaseMakeMap accepts a MakeMakeMap instruction
func (s *BaseSwitcher) CaseMakeMap(inst *ssa.MakeMap) {}

// CaseMakeChan accepts a MakeMakeChan instruction
func (s *BaseSwitcher) CaseMakeChan(inst *ssa.MakeChan) {}

// CaseMakeSlice accepts a MakeSlice instruction
func (s *BaseSwitcher) CaseMakeSlice(inst *ssa.MakeSlice) {}

// CaseSlice accepts a Slice instruction
func (s *BaseSwitcher) CaseSlice(inst *ssa.Slice) {}

// CaseFieldAddr accepts a FieldAddr instruction
func (s *BaseSwitcher) CaseFieldAddr(inst *ssa.FieldAddr) {}

// CaseField accepts a Field instruction
func (s *BaseSwitcher) CaseField(inst *ssa.Field) {}

// CaseIndexAddr accepts an IndexAddr instruction
func (s *BaseSwitcher) CaseIndexAddr(inst *ssa.IndexAddr) {}

// CaseIndex accepts an Index instruction
func (s *BaseSwitcher) CaseIndex(inst *ssa.Index) {}

// CaseLookup accepts a Lookup instruction
func (s *BaseSwitcher) CaseLookup(inst *ssa.Lookup) {}

// CaseSelect accepts a Select instruction
func (s *BaseSwitcher) CaseSelect(inst *ssa.Select) {}

// CaseRange accepts a Range instruction
func (s *BaseSwitcher) CaseRange(inst *ssa.Range) {}

// CaseNext accepts a Next instruction
func (s *BaseSwitcher) CaseNext(inst *ssa.Next) {}

// CaseTypeAssert accepts a TypeAssert instruction
func (s *BaseSwitcher) CaseTypeAssert(inst *ssa.TypeAssert) {}

// CaseExtract accepts an Extract instruction
func (s *BaseSwitcher) CaseExtract(inst *ssa.Extract) {}

// CaseJump accepts a Jump instruction
func (s *BaseSwitcher) CaseJump(inst *ssa.Jump) {}

// CaseIf accepts an If instruction
func (s *BaseSwitcher) CaseIf(inst *ssa.If) {}

// CaseReturn accepts a Return instruction
func (s *BaseSwitcher) CaseReturn(inst *ssa.Return) {}

// CaseRunDefers accepts a RunDefers instruction
func (s *BaseSwitcher) CaseRunDefers(inst *ssa.RunDefers) {}

// CasePanic accepts a Panic instruction
func (s *BaseSwitcher) CasePanic(inst *ssa.Panic) {}

// CaseGo accepts a Go instruction
func (s *BaseSwitcher) CaseGo(inst *ssa.Go) {}

// CaseDefer accepts a Defer instruction
func (s *BaseSwitcher) CaseDefer(inst *ssa.Defer) {}

// CaseSend accepts a Send instruction
func (s *BaseSwitcher) CaseSend(inst *ssa.Send) {}

// CaseStore accepts a Store instruction
func (s *BaseSwitcher) CaseStore(inst *ssa.Store) {}

// CaseMapUpdate accepts a MapUpdate instruction
func (s *BaseSwitcher) CaseMapUpdate(inst *ssa.MapUpdate) {}

// CaseDebugRef accepts a DebugRef instruction
func (s *BaseSwitcher) CaseDebugRef(inst *ssa.DebugRef) {}

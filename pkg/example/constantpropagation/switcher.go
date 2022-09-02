package constantpropagation

import (
	"go/token"
	"math"

	"github.com/cokeBeer/goot/pkg/golang/switcher"
	"golang.org/x/tools/go/ssa"
)

// ConstantPropagationSwitcher represents a constant propagtion switcher
type ConstantPropagationSwitcher struct {
	switcher.BaseSwitcher
	constanctPropagationAnalysis *ConstantPropagationAnalysis
	inMap                        *map[any]any
	outMap                       *map[any]any
}

// CaseBinOp accepts a BinOp instruction
func (s *ConstantPropagationSwitcher) CaseBinOp(inst *ssa.BinOp) {
	v, u, n := s.lookup(inst.X)
	v2, u2, n2 := s.lookup(inst.Y)
	if !u && !u2 && !n && !n2 {
		res, ok := s.evalBinOp(v, v2, inst.Op)
		if ok {
			(*s.outMap)[inst.Name()] = res
		} else {
			(*s.outMap)[inst.Name()] = "NAC"
		}
	} else if n || n2 {
		(*s.outMap)[inst.Name()] = "NAC"
	} else {
		(*s.outMap)[inst.Name()] = "UNDEF"
	}
}

// CasePhi accepts a Phi instruction
func (s *ConstantPropagationSwitcher) CasePhi(inst *ssa.Phi) {
	for _, v := range inst.Edges {
		switch v := (*s.outMap)[v.Name()].(type) {
		case string:
			if v == "NAC" {
				(*s.outMap)[inst.Name()] = "NAC"
				return
			}
		}
	}
	allsame := true
	counti := 0
	i := 0
	for _, v := range inst.Edges {
		switch v := (*s.outMap)[v.Name()].(type) {
		case int:
			if counti == 0 {
				counti++
				i = v
			} else {
				if v != i {
					counti++
					allsame = false
				}
			}
		}
		if allsame == false {
			(*s.outMap)[inst.Name()] = "NAC"
		}
	}
	if counti == 0 {
		(*s.outMap)[inst.Name()] = "UNDEF"
	} else {
		(*s.outMap)[inst.Name()] = i
	}
}

func (s *ConstantPropagationSwitcher) lookup(_v ssa.Value) (int, bool, bool) {
	switch v := (_v).(type) {
	case *ssa.Const:
		return int(v.Int64()), false, false
	default:
		_r := (*s.outMap)[v.Name()]
		switch r := (_r).(type) {
		case string:
			if r == "UNDEF" {
				return 0, true, false
			}
			return 0, false, true
		case int:
			return r, false, false
		}
	}
	return 0, false, false
}

func (s *ConstantPropagationSwitcher) evalBinOp(x int, y int, op token.Token) (int, bool) {
	switch op {
	case token.ADD:
		return x + y, true
	case token.SUB:
		return x - y, true
	case token.MUL:
		return x * y, true
	case token.QUO:
		return x / y, true
	case token.REM:
		return x % y, true
	case token.AND:
		return x & y, true
	case token.OR:
		return x | y, true
	case token.XOR:
		return x ^ y, true
	case token.SHL:
		return x / int(math.Pow(2, float64(y))), true
	case token.SHR:
		return x * int(math.Pow(2, float64(y))), true
	}
	return 0, false
}

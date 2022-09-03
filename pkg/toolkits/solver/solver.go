package solver

import (
	"log"
	"math"
	"reflect"

	"github.com/cokeBeer/goot/pkg/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/toolkits/scalar"
	"github.com/cokeBeer/goot/pkg/util"
	"github.com/cokeBeer/goot/pkg/util/deque"
	"github.com/cokeBeer/goot/pkg/util/entry"
	"github.com/cokeBeer/goot/pkg/util/queue"
	"github.com/dnote/color"
	"golang.org/x/tools/go/ssa"
)

// Solver reprents a flow analysis solver
type Solver struct {
	Analysis scalar.FlowAnalysis
	Debug    bool
}

// Solve constructs a Solver and call Solver.DoAnalysis
func Solve(a scalar.FlowAnalysis, debug bool) {
	s := new(Solver)
	s.Analysis = a
	s.Debug = debug
	s.DoAnalysis()
}

// DoAnalysis solve a FlowAnalysis
func (s *Solver) DoAnalysis() int {
	a := s.Analysis
	universe := s.newUniverse(a.GetGraph(), a.EntryInitalFlow(), a.IsForward())
	inFlow := make(map[any]any)
	outFlow := make(map[any]any)
	s.initFlow(universe, &inFlow, &outFlow)
	q := queue.Of(&universe)
	for numComputations := 0; ; numComputations++ {
		e := q.Poll()
		if e == nil {
			a.End(universe)
			return numComputations
		}
		s.meetFlows(e)
		hasChanged := s.flowThrougth(e)
		if hasChanged {
			for _, o := range e.Out {
				q.Add(o)
			}
		}
		if numComputations > a.Computations() {
			if s.Debug {
				color.Set(color.FgYellow)
				log.Println("has computed", a.GetGraph().Func.String(), "more than max computations, skip")
				color.Unset()
			}
			a.End(universe)
			return numComputations
		}
	}
}

func equal(src map[any]any, dst map[any]any) bool {
	if len(src) != len(dst) {
		return false
	}
	for k, v := range src {
		u, ok := (dst)[k]
		if !ok {
			return false
		}
		same := reflect.DeepEqual(v, u)
		if !same {
			return false
		}
	}
	return true
}

func (s *Solver) flowThrougth(d *entry.Entry) bool {
	if d.InFlow == d.OutFlow {
		return true
	}
	if d.IsRealStronglyConnected {
		out := s.Analysis.NewInitalFlow()
		s.Analysis.FlowThrougth(d.InFlow, d.Data, out)
		if equal(*out, *d.OutFlow) {
			return false
		}
		s.Analysis.Copy(out, d.OutFlow)
		return true
	}
	s.Analysis.FlowThrougth(d.InFlow, d.Data, d.OutFlow)
	return true
}

func (s *Solver) meetFlows(e *entry.Entry) {
	if len(e.In) > 1 {
		copy := true
		for _, o := range e.In {
			if copy {
				copy = false
				s.Analysis.Copy(o.OutFlow, e.InFlow)
			} else {
				s.Analysis.MergeInto(e.Data, e.InFlow, o.OutFlow)
			}
		}
	}
}

func (s *Solver) initFlow(universe []*entry.Entry, in *map[any]any, out *map[any]any) {
	for _, n := range universe {
		if len(n.In) > 1 {
			n.InFlow = s.Analysis.NewInitalFlow()
		} else {
			n.InFlow = n.In[0].OutFlow
		}
		n.OutFlow = s.Analysis.NewInitalFlow()
		(*in)[n.Data] = n.InFlow
		(*out)[n.Data] = n.InFlow
	}
}

func (s *Solver) newUniverse(g *graph.UnitGraph, entryFlow *map[any]any, isForward bool) []*entry.Entry {
	n := g.Size()
	universe := make([]*entry.Entry, 0)
	q := deque.New()
	visited := make(map[ssa.Instruction]*entry.Entry)
	superEntry := entry.New(nil, nil)
	var entries []ssa.Instruction
	var actualEntries []ssa.Instruction
	if isForward {
		actualEntries = g.Heads
	} else {
		actualEntries = g.Tails
	}
	if len(actualEntries) != 0 {
		entries = actualEntries
	} else {
		if isForward {
			if s.Debug {
				color.Set(color.FgYellow)
				log.Println("error: no entry point for method in forward analysis")
				color.Unset()
			}
		} else {
			entries = make([]ssa.Instruction, 0)
			head := g.Heads[0]
			visitedNodes := make(map[any]any)
			worklist := make([]ssa.Instruction, 0)
			worklist = append(worklist, head)
			var current ssa.Instruction
			for len(worklist) != 0 {
				current = worklist[0]
				worklist = worklist[1:]
				visitedNodes[current] = true
				switch node := current.(type) {
				case *ssa.Jump:
					entries = append(entries, node)
				}
				for _, next := range g.GetSuccs(current) {
					if util.Collision(&visitedNodes, next) {
						continue
					}
					worklist = append(worklist, next)
				}
			}
			if len(entries) == 0 {
				log.Fatal("error: backward analysis on an empty entry set.")
			}
		}
	}
	visitEntry(visited, superEntry, entries)
	superEntry.InFlow = entryFlow
	superEntry.OutFlow = entryFlow
	sv := make([]*entry.Entry, n)
	si := make([]int, n)
	index := 0
	i := 0
	v := superEntry
	for {
		if i < len(v.Out) {
			w := v.Out[i]
			i++
			if w.Number == math.MinInt {
				w.Number = q.Len()
				q.AddLast(w)
				if isForward {
					visitEntry(visited, w, g.GetSuccs(w.Data))
				} else {
					visitEntry(visited, w, g.GetPreds(w.Data))
				}
				si[index] = i
				sv[index] = v
				index++
				i = 0
				v = w
			}
		} else {
			if index == 0 {
				for i, j := 0, len(universe)-1; i < j; i, j = i+1, j-1 {
					universe[i], universe[j] = universe[j], universe[i]
				}
				return universe
			}
			universe = append(universe, v)
			sccPop(q, v)
			index--
			v = sv[index]
			i = si[index]
		}
	}
}

func visitEntry(visited map[ssa.Instruction]*entry.Entry, v *entry.Entry, out []ssa.Instruction) []*entry.Entry {
	n := len(out)
	a := make([]*entry.Entry, n)
	for i := 0; i < n; i++ {
		a[i] = getEntryOf(visited, out[i], v)
	}
	v.Out = a
	return a
}

func getEntryOf(visited map[ssa.Instruction]*entry.Entry, d ssa.Instruction, v *entry.Entry) *entry.Entry {
	newEntry := entry.New(d, v)
	var oldEntry *entry.Entry
	if _, ok := visited[d]; ok {
		oldEntry = visited[d]
	} else {
		visited[d] = newEntry
		oldEntry = nil
	}
	if oldEntry == nil {
		return newEntry
	}
	if oldEntry == v {
		oldEntry.IsRealStronglyConnected = true
	}
	oldEntry.In = append(oldEntry.In, v)
	return oldEntry
}

func sccPop(s *deque.Deque, v *entry.Entry) {
	min := v.Number
	for _, e := range v.Out {
		if e.Number < min {
			min = e.Number
		}
	}
	if min != v.Number {
		v.Number = min
		return
	}

	w := s.PollLast()
	w.Number = math.MaxInt
	if w == v {
		return
	}
	w.IsRealStronglyConnected = true
	for {
		w = s.PollLast()
		w.IsRealStronglyConnected = true
		w.Number = math.MaxInt
		if w == v {
			return
		}
	}
}

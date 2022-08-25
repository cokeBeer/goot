package solver

import (
	"go/ast"
	"log"
	"math"
	"reflect"

	"github.com/cokeBeer/goot/pkg/toolkits/graph"
	"github.com/cokeBeer/goot/pkg/toolkits/scalar"
	"github.com/cokeBeer/goot/pkg/util"
	"github.com/cokeBeer/goot/pkg/util/deque"
	"github.com/cokeBeer/goot/pkg/util/entry"
	"github.com/cokeBeer/goot/pkg/util/queue"
)

// Solver reprents a flow analysis solver
type Solver struct {
	Analysis scalar.FlowAnalysis
}

// Solve constructs a Solver and call Solver.DoAnalysis
func Solve(a scalar.FlowAnalysis) {
	s := new(Solver)
	s.Analysis = a
	s.DoAnalysis()
}

// DoAnalysis solve a FlowAnalysis
func (s *Solver) DoAnalysis() int {
	a := s.Analysis
	universe := newUniverse(a.GetGraph(), a.EntryInitalFlow(), a.IsForward())
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
	}
}

func (s *Solver) flowThrougth(d *entry.Entry) bool {
	if d.InFlow == d.OutFlow {
		return true
	}
	if d.IsRealStronglyConnected {
		out := s.Analysis.NewInitalFlow()
		s.Analysis.FlowThrougth(d.InFlow, d.Data, out)
		if reflect.DeepEqual(*out, *d.OutFlow) {
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

func newUniverse(g *graph.NodeGraph, entryFlow *map[any]any, isForward bool) []*entry.Entry {
	n := g.Size()
	universe := make([]*entry.Entry, 0)
	s := deque.New()
	visited := make(map[ast.Node]*entry.Entry)
	superEntry := entry.New(nil, nil)
	var entries []ast.Node
	var actualEntries []ast.Node
	if isForward {
		actualEntries = g.Heads
	} else {
		actualEntries = g.Tails
	}
	if len(actualEntries) != 0 {
		entries = actualEntries
	} else {
		if isForward {
			log.Fatal("error: no entry point for method in forward analysis")
		} else {
			entries = make([]ast.Node, 0)
			head := g.Heads[0]
			visitedNodes := make(map[any]any)
			worklist := make([]ast.Node, 0)
			worklist = append(worklist, head)
			var current ast.Node
			for len(worklist) != 0 {
				current = worklist[0]
				worklist = worklist[1:]
				visitedNodes[current] = true
				switch node := current.(type) {
				case *ast.GoStmt:
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
				w.Number = s.Len()
				s.AddLast(w)
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
			sccPop(s, v)
			index--
			v = sv[index]
			i = si[index]
		}
	}
}

func visitEntry(visited map[ast.Node]*entry.Entry, v *entry.Entry, out []ast.Node) []*entry.Entry {
	n := len(out)
	a := make([]*entry.Entry, n)
	for i := 0; i < n; i++ {
		a[i] = getEntryOf(visited, out[i], v)
	}
	v.Out = a
	return a
}

func getEntryOf(visited map[ast.Node]*entry.Entry, d ast.Node, v *entry.Entry) *entry.Entry {
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

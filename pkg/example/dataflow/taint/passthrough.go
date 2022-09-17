package taint

// PassThrough represents a passthrough
type PassThrough struct {
	Names   []string
	Recv    *TaintWrapper
	Results []*TaintWrapper
	Params  []*TaintWrapper
}

// PassThroughCache represents a passthrough cache
type PassThroughCache struct {
	Recv    []int
	Results [][]int
	Params  [][]int
}

// NewPassThrough return a PassThrough
func NewPassThrough(names []string, recv bool, result int, param int) *PassThrough {
	passThrough := new(PassThrough)
	passThrough.Names = names
	passThrough.Results = make([]*TaintWrapper, 0)
	passThrough.Params = make([]*TaintWrapper, 0)
	// init param taints in passThrough
	if recv {
		// if the function has a receiver, add a position for receiver's taint
		recv := NewTaintWrapper(names[0])
		passThrough.Recv = recv
	}

	for i := 0; i < result; i++ {
		passThrough.Results = append(passThrough.Results, NewTaintWrapper())
	}

	for i := 0; i < param; i++ {
		passThrough.Params = append(passThrough.Params, NewTaintWrapper(passThrough.ParamName(i)))
	}

	return passThrough
}

// ToCache tranforms a passthrough to a passthrough cache
func (p *PassThrough) ToCache() *PassThroughCache {
	passThroughCache := NewPassThroughCache(false, 0, 0)
	n := len(p.Names)
	if p.HasRecv() {
		singlePassThrough := make([]int, 0)
		for i := 0; i < n; i++ {
			// for reciver, checks its taints from which param, and records
			if ok := p.Recv.HasTaint(p.Names[i]); ok {
				singlePassThrough = append(singlePassThrough, i)
			}
		}
		passThroughCache.Recv = singlePassThrough
	}
	m := p.ResultNum()
	for i := 0; i < m; i++ {
		singlePassThrough := make([]int, 0)
		for j := 0; j < n; j++ {
			// for every return value, checks its taints from which param, and records
			if ok := p.Results[i].HasTaint(p.Names[j]); ok {
				singlePassThrough = append(singlePassThrough, j)
			}
		}
		passThroughCache.Results = append(passThroughCache.Results, singlePassThrough)
	}
	m = p.ParamNum()
	for i := 0; i < m; i++ {
		singlePassThrough := make([]int, 0)
		for j := 0; j < n; j++ {
			// for every parameter value, checks its taints from which param, and records
			if ok := p.Params[i].HasTaint(p.Names[j]); ok {
				singlePassThrough = append(singlePassThrough, j)
			}
		}
		passThroughCache.Params = append(passThroughCache.Params, singlePassThrough)
	}
	return passThroughCache
}

// RecvName returns the receiver's name
func (p *PassThrough) RecvName() string {
	if p.HasRecv() {
		return p.Names[0]
	}
	return ""
}

// ParamName returns the i'th param's name
func (p *PassThrough) ParamName(i int) string {
	if p.HasRecv() {
		return p.Names[i+1]
	}
	return p.Names[i]
}

// HasRecv returns whether the function has a receiver
func (p *PassThrough) HasRecv() bool {
	return p.Recv != nil
}

// ResultNum returns number of results
func (p *PassThrough) ResultNum() int {
	return len(p.Results)
}

// ParamNum returns number of params
func (p *PassThrough) ParamNum() int {
	return len(p.Params)
}

// NewPassThroughCache returns a PassThroughCache
func NewPassThroughCache(recv bool, result int, param int) *PassThroughCache {
	passThroughCache := new(PassThroughCache)
	passThroughCache.Results = make([][]int, 0)
	passThroughCache.Params = make([][]int, 0)
	if recv {
		passThroughCache.Recv = make([]int, 0)
	}
	for i := 0; i < result; i++ {
		passThroughCache.Results = append(passThroughCache.Results, make([]int, 0))
	}
	for i := 0; i < param; i++ {
		passThroughCache.Params = append(passThroughCache.Results, make([]int, 0))
	}
	return passThroughCache
}

// HasRecv returns whether the function has a receiver
func (c *PassThroughCache) HasRecv() bool {
	return c.Recv != nil
}

// ResultNum returns number of results
func (c *PassThroughCache) ResultNum() int {
	return len(c.Results)
}

// ParamNum returns number of params
func (c *PassThroughCache) ParamNum() int {
	return len(c.Params)
}

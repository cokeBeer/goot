package taint

type TaintWrapper struct {
	innerTaint *map[string]bool
}

// NewTaintWrapper returns a TaintWrapper
func NewTaintWrapper(taints ...string) *TaintWrapper {
	newTaint := new(TaintWrapper)
	innnerTaint := make(map[string]bool)
	for _, taint := range taints {
		innnerTaint[taint] = true
	}
	newTaint.innerTaint = &innnerTaint
	return newTaint
}

// AddTaint adds taints to innerTaint
func (w *TaintWrapper) AddTaint(taints ...string) {
	for _, taint := range taints {
		(*w.innerTaint)[taint] = true
	}
}

// HasTaint returns whether innerTaint has the taint
func (w *TaintWrapper) HasTaint(taint string) bool {
	_, ok := (*w.innerTaint)[taint]
	return ok
}

// GetTaint returns innerTaint
func GetTaint(flow *map[any]any, name string) *map[string]bool {
	return GetTaintWrapper(flow, name).innerTaint
}

// InheritTaint inherits taints from a wrapper with key
func (w *TaintWrapper) InheritTaint(flow *map[any]any, name string) {
	oldTaint := GetTaintWrapper(flow, name)
	for taint := range *oldTaint.innerTaint {
		(*w.innerTaint)[taint] = true
	}
}

// GetTaintWrapper gets wrapper with a key
func GetTaintWrapper(flow *map[any]any, name string) *TaintWrapper {
	if _oldTaint, ok := (*flow)[name]; ok {
		oldTaint := _oldTaint.(*TaintWrapper)
		return oldTaint
	}
	return SetTaintWrapper(flow, name, NewTaintWrapper())
}

// SetTaintWrapper sets wrapper wtih a key
func SetTaintWrapper(flow *map[any]any, name string, wrapper *TaintWrapper) *TaintWrapper {
	(*flow)[name] = wrapper
	return wrapper
}

// PassTaint passes taint from a wrapper with key to another with key
func PassTaint(flow *map[any]any, dst string, src ...string) {
	dstTaint := GetTaintWrapper(flow, dst)
	for _, name := range src {
		dstTaint.InheritTaint(flow, name)
	}
}

// SetTaint set innerTaint for a wrapper with a key
func SetTaint(flow *map[any]any, name string, taints ...string) {
	wrapper := GetTaintWrapper(flow, name)
	wrapper.AddTaint(taints...)
}

// MergeTaintWrapper merges wrapper with same key from in flow to inout flow
func MergeTaintWrapper(inout *map[any]any, in *map[any]any, name string) {
	wrapper := GetTaintWrapper(inout, name)
	wrapper.InheritTaint(in, name)
}

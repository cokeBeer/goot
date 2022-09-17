package rule

// BaseRuler represents a base implementation of rule.Ruler
type BaseRuler struct {
}

// NewBaseRuler returns a BaseRuler
func NewBaseRuler(moduleName ...string) *BaseRuler {
	baseRuler := new(BaseRuler)
	return baseRuler
}

// IsSource returns whether a node is a source
func (r *BaseRuler) IsSource(_f any) bool {
	source := make(map[string]bool)
	switch f := _f.(type) {
	case string:
		_, ok := source[f]
		if ok {
			return true
		}
	}
	return false
}

// IsSink returns whether a node is a sink
func (r *BaseRuler) IsSink(_f any) bool {
	return false
}

// IsIntra returns whether a node is from target module
func (r *BaseRuler) IsIntra(_f any) bool {
	return false
}

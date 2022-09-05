package rule

// Ruler defines whether a node is interesting in taint analysis
type Ruler interface {
	IsSink(any) bool
	IsSource(any) bool
	IsIntro(any) bool
}

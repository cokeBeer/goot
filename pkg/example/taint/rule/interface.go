package rule

type Ruler interface {
	IsSink(any) bool
	IsSource(any) bool
	IsIntro(any) bool
}

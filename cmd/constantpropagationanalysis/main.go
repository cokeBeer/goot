package main

import (
	"github.com/cokeBeer/goot/pkg/example/dataflow/constantpropagation"
)

const src = `package main

func Hello(a int, b int) bool {
	a = 1
	x := a + 3
	y := b + 2
	if x > y {
		x = x + 1
	} else {
		x = y + 1
	}
	w := x > 0
	return w
}`

func main() {
	runner := constantpropagation.NewRunner(src, "Hello")
	runner.Run()
}

package main

import "github.com/cokeBeer/goot/pkg/example/taint"

func main() {
	pkg := taint.Gostd
	runner := taint.NewRunner(pkg...)
	runner.SrcPath = "passthrough.json"
	runner.DstPath = "passthrough.json"
	runner.Debug = true
	runner.Run()
}

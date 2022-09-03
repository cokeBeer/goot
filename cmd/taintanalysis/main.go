package main

import "github.com/cokeBeer/goot/pkg/example/taint"

func main() {
	//pkg := taint.Gostd
	runner := taint.NewRunner("fmt...")
	runner.SrcPath = "passthrough.json"
	runner.DstPath = "passthrough.json"
	runner.Debug = true
	runner.Run()
}

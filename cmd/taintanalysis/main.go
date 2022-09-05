package main

import "github.com/cokeBeer/goot/pkg/example/taint"

func main() {
	// the ../../ takes you back to root of the project
	// and the ... means scan packages in package pkg recursively
	runner := taint.NewRunner("../../pkg/bench...")
	// the module name is the name defined in go.mod
	runner.ModuleName = "github.com/cokeBeer/goot"
	runner.PassThroughSrcPath = ""
	runner.PassThroughDstPath = "passthrough.json"
	runner.CallGraphDstPath = "callgraph.json"
	runner.PassThroughOnly = false
	runner.InitOnly = false
	runner.Debug = true
	runner.Run()
}

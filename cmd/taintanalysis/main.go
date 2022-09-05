package main

import "github.com/cokeBeer/goot/pkg/example/taint"

func main() {
	//pkg := taint.Gostd
	runner := taint.NewRunner(taint.Gostd...)
	runner.ModuleName = ""
	runner.PassThroughSrcPath = ""
	runner.PassThroughDstPath = "passthrough.json"
	runner.CallGraphDstPath = "callgraph.json"
	runner.PassThroughOnly = false
	runner.InitOnly = false
	runner.Debug = true
	runner.Run()
}

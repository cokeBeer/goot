package main

import (
	"log"

	"github.com/cokeBeer/goot/pkg/example/dataflow/taint"
)

func main() {
	// the ../../ takes you back to root of the project
	// and the ... means scan packages in package pkg recursively
	runner := taint.NewRunner("../../pkg/main")
	// the module name is the name defined in go.mod
	runner.ModuleName = "github.com/cokeBeer/goot"
	//runner.PassThroughSrcPath = []string{"gostd1.19.json", "additional.json"}
	runner.PassThroughDstPath = "passthrough.json"
	runner.TaintGraphDstPath = "taintgraph.json"
	runner.UsePointerAnalysis = true
	runner.PassThroughOnly = true
	runner.InitOnly = false
	runner.Debug = true
	runner.PersistToNeo4j = false
	runner.TargetFunc = ""
	runner.Neo4jURI = "bolt://localhost:7687"
	runner.Neo4jUsername = "neo4j"
	runner.Neo4jPassword = "password"
	runner.PassBack = true
	err := runner.Run()
	if err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"log"

	"github.com/cokeBeer/goot/pkg/example/dataflow/taint"
)

func main() {
	// the ../../ takes you back to root of the project
	// and the ... means scan packages in package pkg recursively
	runner := taint.NewRunner("github.com/gorilla/schema")
	// the module name is the name defined in go.mod
	runner.ModuleName = "github.com/cokeBeer/goot"
	runner.PassThroughSrcPath = []string{"gostd1.19.json", "additional.json"}
	runner.PassThroughDstPath = "passthrough.json"
	runner.CallGraphDstPath = "callgraph.json"
	runner.PassThroughOnly = true
	runner.InitOnly = false
	runner.Debug = true
	runner.PersistToNeo4j = true
	runner.TargetFunc = "(*github.com/gorilla/schema.Decoder).Decode"
	runner.Neo4jURI = "bolt://localhost:7687"
	runner.Neo4jUsername = "neo4j"
	runner.Neo4jPassword = "password"
	runner.PassBack = true
	err := runner.Run()
	if err != nil {
		log.Fatal(err)
	}
}

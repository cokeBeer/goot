# Taint
## OPTIONS
I write a runner to help you use taint analysis\
You can set options directly on a Runner like
```go
runner := taint.NewRunner("relative/path/to/package")
runner.ModuleName = "module-name"
runner.PassThroughDstPath = "passthrough.json"
runner.CallGraphDstPath = "callgraph.json"
```
All options are:

  - `ModuleName`(necessary): the target module's name, often in go.mod
  - `PkgPath`(necessary): the target packages' relative path, it is important that you should write analysis file in same project. e.g. `cmd/myanalysis/main.go`, in case go can't find target packages
  - `Debug`(optional): when set true, output debug information, default `false`
  - `InitOnly`(optional): when set true, only analysis init functions, default `false`
  - `PassThroughOnly`(optional): when set true only do passthrough analysis, default `false`
  - `PassThroughSrcPath`(optional): path to passthrough sources, you can use it to accelerate analysis or add additional passthrough, default `[]string{}`
  - `PassThroughDstPath`(optional): path to save passthrough output, default `""`
  - `TaintGraphDstPath`(optional): path to save taint edge output, default `""`
  - `Ruler `(optional): ruler is interface that defines how to decide whether a node is sink, source or intra. You can implements it, default [DummyRuler](ruler.go)
  - `PersistToNeo4j`(optional): when set true, save nodes and edges to neo4j, default `false`
  - `Neo4jUsername`(optiosnal): neo4j usename, default `""`
  - `Neo4jPassword`(optional): neo4j password, default `""`
  - `Neo4jURI`(optional): neo4j uri, default `""`
  - `TargetFunc`(optional): when set, only analysis target function and output its SSA, default `""`
  - `UsePointerAnalysis`(optional): when set, use pointer analysis to help selecting callee, default `false`.  ⚠️ note that if you set this true, the `PkgPath` option can only contain main packages

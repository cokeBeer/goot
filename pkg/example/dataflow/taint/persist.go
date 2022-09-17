package taint

import (
	"encoding/json"
	"fmt"
	"hash/maphash"
	"io"
	"log"
	"os"
	"strconv"

	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

// PersistPassThrough stores passthrough data to target destination
func PersistPassThrough(passThroughContainer *map[string]*PassThroughCache, dst string) error {
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	res, err := json.Marshal(*passThroughContainer)
	if err != nil {
		return err
	}
	fmt.Fprint(f, string(res))
	f.Close()
	return nil
}

// PersistTaintGraph stores taint edges to target destination
func PersistTaintGraph(edges *map[string]*Edge, dst string) error {
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	res, err := json.Marshal(*edges)
	if err != nil {
		return err
	}
	fmt.Fprint(f, string(res))
	f.Close()
	return nil
}

// PersistToNeo4j stores taint edges to neo4j database
func PersistToNeo4j(nodes *map[string]*Node, edges *map[string]*Edge, uri string, username string, password string) {
	driver, err := neo4j.NewDriver(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		log.Fatal(err)
	}
	defer driver.Close()

	session := driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()
	seed := maphash.MakeSeed()
	for _, node := range *nodes {
		id := strconv.FormatUint(maphash.String(seed, node.Canonical+strconv.Itoa(node.Index)), 10)
		_, err = session.WriteTransaction(func(transaction neo4j.Transaction) (any, error) {
			if node.IsSource && node.IsIntra && len(node.Out) != 0 {
				_, _ = transaction.Run(
					"CREATE (node:Source) SET node={id:$Id, name:$Canonical, index:$Index}",
					map[string]any{"Id": id, "Canonical": node.Canonical, "Index": node.Index})
			} else if node.IsSink && len(node.In) != 0 {
				_, _ = transaction.Run(
					"CREATE (node:Sink) SET node={id:$Id, name:$Canonical, index:$Index}",
					map[string]any{"Id": id, "Canonical": node.Canonical, "Index": node.Index})
			} else if node.IsIntra && len(node.In)+len(node.Out) != 0 {
				_, _ = transaction.Run(
					"CREATE (node:Intra) SET node={id:$Id, name:$Canonical, index:$Index}",
					map[string]any{"Id": id, "Canonical": node.Canonical, "Index": node.Index})
			}
			return nil, nil
		})
		if err != nil {
			log.Fatal(err)
		}
	}
	for _, edge := range *edges {
		id1 := strconv.FormatUint(maphash.String(seed, edge.From+strconv.Itoa(edge.FromIndex)), 10)
		id2 := strconv.FormatUint(maphash.String(seed, edge.To+strconv.Itoa(edge.ToIndex)), 10)
		_, err = session.WriteTransaction(func(transaction neo4j.Transaction) (any, error) {
			_, _ = transaction.Run(
				"MATCH (from),(to) WHERE from.id=$Id1 and to.id=$Id2 CREATE (from)-[r:CALL]->(to)",
				map[string]any{"Id1": id1, "Id2": id2})
			return nil, nil
		})
		if err != nil {
			log.Fatal(err)
		}
	}
}

// FetchPassThrough loads passthrougth data from target source
func FetchPassThrough(passThroughContainer *map[string]*PassThroughCache, src []string) error {
	for _, path := range src {
		tmp := make(map[string]*PassThroughCache)
		f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0666)
		if err != nil {
			return err
		}
		res, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		err = json.Unmarshal(res, &tmp)
		if err != nil {
			return err
		}
		for k, v := range tmp {
			(*passThroughContainer)[k] = v
		}
	}
	return nil
}

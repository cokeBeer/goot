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
func PersistPassThrough(passThroughContainer *map[string][][]int, dst string) error {
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

// PersistCallGraph stores passthrough data to target destination
func PersistCallGraph(edges *map[string]*Edge, dst string) error {
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
			if node.IsSink {
				_, _ = transaction.Run(
					"CREATE (node:Sink) SET node={id:$Id, name:$Canonical, index:$Index}",
					map[string]any{"Id": id, "Canonical": node.Canonical, "Index": node.Index})
			} else if node.IsIntra {
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
func FetchPassThrough(passThroughContainer *map[string][][]int, src string) error {
	f, err := os.OpenFile(src, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	res, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	err = json.Unmarshal(res, passThroughContainer)
	if err != nil {
		return err
	}
	return nil
}

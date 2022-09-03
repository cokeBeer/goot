package taint

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Persist stores passthrough data to target destination
func Persist(passThroughContainer *map[string][][]int, dst string) error {
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

// Fetch loads passthrougth data from target source
func Fetch(passThroughContainer *map[string][][]int, src string) error {
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

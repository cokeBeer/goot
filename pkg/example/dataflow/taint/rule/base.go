package rule

import (
	"strings"
)

// BaseRuler represents a base implementation of rule.Ruler
type BaseRuler struct {
	moduleName []string
}

// New returns a BaseRuler
func New(moduleName ...string) *BaseRuler {
	baseRuler := new(BaseRuler)
	baseRuler.moduleName = moduleName
	return baseRuler
}

// IsSource returns whether a node is a source
func (r *BaseRuler) IsSource(_f any) bool {
	source := make(map[string]bool)
	switch f := _f.(type) {
	case string:
		_, ok := source[f]
		if ok {
			return true
		}
	}
	return false
}

// IsSink returns whether a node is a sink
func (r *BaseRuler) IsSink(_f any) bool {
	sink := make(map[string]bool)
	// cmdi
	sink["os/exec.Command"] = true
	sink["os/exec.CommandContext"] = true
	sink["syscall.Exec"] = true
	sink["syscall.ForkExec"] = true
	sink["syscall.StartProcess"] = true
	// sqli
	sink["(*database/sql.DB).Exec"] = true
	sink["(*database/sql.DB).ExecContext"] = true
	sink["(*database/sql.DB).Query"] = true
	sink["(*database/sql.DB).QueryContext"] = true
	sink["(*database/sql.DB).QueryRow"] = true
	sink["(*database/sql.DB).QueryRowContext"] = true
	// ssrf
	sink["net/http.Get"] = true
	sink["net/http.Head"] = true
	sink["net/http.Post"] = true
	sink["net/http.PostForm"] = true
	sink["(*net/http.Client).Do"] = true
	sink["(*net/http.Client).Get"] = true
	sink["(*net/http.Client).Head"] = true
	sink["(*net/http.Client).Post"] = true
	sink["(*net/http.Client).PostForm"] = true
	// traversal
	sink["os.Create"] = true
	sink["os.Open"] = true
	sink["os.OpenFile"] = true
	sink["os.ReadFile"] = true
	sink["io/ioutil.ReadFile"] = true
	sink["io/ioutil.WriteFile"] = true

	switch f := _f.(type) {
	case string:
		_, ok := sink[f]
		if ok {
			return true
		}
	}
	return false
}

// IsIntra returns whether a node is from target module
func (r *BaseRuler) IsIntra(_f any) bool {
	switch f := (_f).(type) {
	case string:
		for _, name := range r.moduleName {
			if strings.HasPrefix(f, name) {
				return true
			} else if strings.HasPrefix(f, "("+name) {
				return true
			} else if strings.HasPrefix(f, "(*"+name) {
				return true
			}
		}
	}
	return false
}

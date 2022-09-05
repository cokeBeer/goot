package rule

import "strings"

type BaseRuler struct {
	moduleName []string
}

func New(moduleName ...string) *BaseRuler {
	baseRuler := new(BaseRuler)
	baseRuler.moduleName = moduleName
	return baseRuler
}

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

func (r *BaseRuler) IsSink(_f any) bool {
	sink := make(map[string]bool)
	sink["os/exec.Command"] = true
	sink["io/ioutil.ReadFile"] = true
	sink["(*database/sql.DB).QueryRow"] = true
	sink["net/http.Get"] = true
	switch f := _f.(type) {
	case string:
		_, ok := sink[f]
		if ok {
			return true
		}
	}
	return false
}

func (r *BaseRuler) IsIntro(_f any) bool {
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

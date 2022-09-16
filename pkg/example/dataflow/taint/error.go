package taint

type NoMainPkgError struct {
}

func (e *NoMainPkgError) Error() string {
	return "No main package found in runner.PkgPath"
}

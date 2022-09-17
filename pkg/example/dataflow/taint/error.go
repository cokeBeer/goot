package taint

// NoMainPkgError represents a no main package error
type NoMainPkgError struct {
}

func (e *NoMainPkgError) Error() string {
	return "No main package found in runner.PkgPath"
}

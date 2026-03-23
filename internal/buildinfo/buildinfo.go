package buildinfo

import "fmt"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Info struct {
	Name    string
	Version string
	Commit  string
	Date    string
}

func Current(name string) Info {
	return Info{
		Name:    name,
		Version: Version,
		Commit:  Commit,
		Date:    Date,
	}
}

func (info Info) String() string {
	return fmt.Sprintf("%s version %s (commit=%s date=%s)", info.Name, info.Version, info.Commit, info.Date)
}

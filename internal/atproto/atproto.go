package atproto

import "regexp"

var didRegex = regexp.MustCompile("^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$")

func IsDID(value string) bool {
	return didRegex.MatchString(value)
}

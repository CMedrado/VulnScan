package check

import "strings"

func IsValidType(fileName string, types []string) bool {
	for _, t := range types {
		t = strings.TrimSpace(t)
		if t == "all" || strings.HasSuffix(fileName, t) {
			return true
		}
	}
	return false
}

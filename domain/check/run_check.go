package check

import (
	"regexp"
	"strings"

	"github.com/CMedrado/VulnScan/domain/entities"
)

var (
	XSSCheck  = entities.Check{Name: "XSS", RegularExpression: `(?i)alert\s*\([^)]*\)`, DocumentTypes: []string{"html", "js"}}
	SQLICheck = entities.Check{Name: "SQL Injection", RegularExpression: `(?si)\"[^\"]*?SELECT.*?WHERE.*?%s.*?\"`, DocumentTypes: []string{"all"}}
)

func RunCheck(file entities.File, check entities.Check) []entities.Finding {
	if !IsValidType(file.Name, check.DocumentTypes) {
		return []entities.Finding{
			{
				Path:      file.Name,
				NameCheck: check.Name,
				Content:   "document type wrong",
				Line:      0,
			},
		}
	}

	r := regexp.MustCompile(check.RegularExpression)
	matches := r.FindAllString(file.Content, -1)

	results := make([]entities.Finding, 0, len(matches))
	var line int
	actual := 0
	for _, match := range matches {
		lines := strings.Split(file.Content, "\n")

		for i := actual; i < len(lines); i++ {
			part := strings.Split(match, "\n")

			if strings.Contains(lines[i], part[0]) {
				line = i + 1
				actual = i
				break
			}
		}

		results = append(results, entities.Finding{
			Path:      file.Name,
			NameCheck: check.Name,
			Content:   strings.ReplaceAll(match, "\n", " "),
			Line:      line,
		})
	}

	return results
}

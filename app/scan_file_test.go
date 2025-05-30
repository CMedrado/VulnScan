package app_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CMedrado/VulnScan/app"
	"github.com/CMedrado/VulnScan/domain/entities"
)

func TestScanFile_Success(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		enableXSS bool
		enableSQL bool
		newCheck  string
		expected  []entities.Finding
	}{
		{
			name:      "should return alert vulnerability to sql and xss",
			path:      "./test/xss.html",
			enableXSS: true,
			enableSQL: true,
			expected: []entities.Finding{
				{
					Path:      "./test/xss.html",
					NameCheck: "XSS",
					Content:   "alert(\"XSS detectado!\")",
					Line:      8,
				},
				{
					Path:      "./test/xss.html",
					NameCheck: "SQL Injection",
					Content:   "\"SELECT * FROM contas WHERE usuario = '%s'\"",
					Line:      9,
				},
			},
		},
		{
			name:      "should return alert vulnerability to sql",
			path:      "./test/sql.go",
			enableXSS: false,
			enableSQL: true,
			expected: []entities.Finding{
				{
					Path:      "./test/sql.go",
					NameCheck: "SQL Injection",
					Content:   "\"SELECT * FROM contas //\t\tWHERE usuario = '%s'\"",
					Line:      13,
				},
			},
		},
		{
			name:      "should return alert vulnerability to xss",
			path:      "./test/xss.html",
			enableXSS: true,
			enableSQL: false,
			expected: []entities.Finding{
				{
					Path:      "./test/xss.html",
					NameCheck: "XSS",
					Content:   "alert(\"XSS detectado!\")",
					Line:      8,
				},
			},
		},
		{
			name:      "should return alert vulnerability to new check",
			path:      "./test/new_check.html",
			enableXSS: false,
			enableSQL: false,
			newCheck:  "(?i)document\\.write\\s*\\(.*?\\),html,js",
			expected: []entities.Finding{
				{
					Path:      "./test/new_check.html",
					NameCheck: "Custom Check",
					Content:   "document.write(\"<h1>XSS via document.write</h1>\")",
					Line:      4,
				},
			},
		},
		{
			name:      "should return no vulnerability",
			path:      "./test/no_vulnerabilities.go",
			enableXSS: false,
			enableSQL: true,
			expected:  nil,
		},

		{
			name:      "should return type wrong",
			path:      "./test/sql.go",
			enableXSS: true,
			enableSQL: false,
			expected: []entities.Finding{
				{
					Path:      "./test/sql.go",
					NameCheck: "XSS",
					Content:   "document type wrong",
					Line:      0,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := app.Config{
				Path:       tt.path,
				EnableXSS:  tt.enableXSS,
				EnableSQLi: tt.enableSQL,
				NewCheck:   tt.newCheck,
			}
			results, err := app.ScanFile(cfg)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.expected, results)
		})
	}
}

func TestScanFile_Failure(t *testing.T) {
	t.Run("should return error for invalid file", func(t *testing.T) {
		cfg := app.Config{
			Path:      "./test/sql.html",
			EnableXSS: true,
		}
		_, err := app.ScanFile(cfg)
		require.Error(t, err)
	})
}

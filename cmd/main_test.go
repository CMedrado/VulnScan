package main_test

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CMedrado/VulnScan/app"
)

func TestMain_Success(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "should return alert vulnerability to xss",
			args:     []string{"run", "./main.go", "--path=.././app/test/xss.html", "--xss"},
			expected: "🔴 [.././app/test/xss.html:8] XSS => Match: alert(\"XSS detectado!\")\n",
		},
		{
			name:     "should return alert vulnerability to sql",
			args:     []string{"run", "./main.go", "--path=.././app/test/sql.text", "--sqli"},
			expected: "🔴 [.././app/test/sql.text:13] SQL Injection => Match: \"SELECT * FROM contas //\t\tWHERE usuario = '%s'\"\n",
		},
		{
			name:     "should return alert vulnerability to xss and sql",
			args:     []string{"run", "./main.go", "--path=.././app/test/xss.html", "--xss", "--sqli"},
			expected: "🔴 [.././app/test/xss.html:8] XSS => Match: alert(\"XSS detectado!\")\n🔴 [.././app/test/xss.html:9] SQL Injection => Match: \"SELECT * FROM contas WHERE usuario = '%s'\"\n",
		},
		{
			name:     "should return alert vulnerability to new check",
			args:     []string{"run", "./main.go", "--path=.././app/test/new_check.html", "--new_check=(?i)document\\.write\\s*\\(.*?\\),html,js"},
			expected: "🔴 [.././app/test/new_check.html:4] Custom Check => Match: document.write(\"<h1>XSS via document.write</h1>\")\n",
		},
		{
			name:     "should return no vulnerability",
			args:     []string{"run", "./main.go", "--path=.././app/test/no_vulnerabilities.text", "--sqli"},
			expected: "✅ No vulnerabilities found!\n",
		},
		{
			name:     "should return type wrong (no match due to file type)",
			args:     []string{"run", "./main.go", "--path=.././app/test/sql.text", "--xss"},
			expected: "🔴 [.././app/test/sql.text:0] XSS => Match: document type wrong\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd := exec.Command("go", tt.args...)

			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Logf("Erro: %v\nSaída:\n%s", err, output)
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(output))
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

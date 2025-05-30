package check_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CMedrado/VulnScan/domain/check"
)

func TestCheckType_Success(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		types    []string
		result   bool
	}{
		{
			name:     "should return true with space",
			fileName: "./test/xss.html",
			types:    []string{" go", " html "},
			result:   true,
		},
		{
			name:     "should return true without space",
			fileName: "./test/xss.html",
			types:    []string{"go", "html"},
			result:   true,
		},
		{
			name:     "should return true with spot",
			fileName: "./test/xss.html",
			types:    []string{".go", ".html"},
			result:   true,
		},
		{
			name:     "should return true with type is all",
			fileName: "./test/xss.html",
			types:    []string{"all"},
			result:   true,
		},
		{
			name:     "should return false",
			fileName: "./test/xss.html",
			types:    []string{".go"},
			result:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := check.IsValidType(tt.fileName, tt.types)
			assert.Equal(t, tt.result, results)
		})
	}
}

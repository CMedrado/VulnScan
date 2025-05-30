package app

import (
	"os"
	"strings"

	"github.com/CMedrado/VulnScan/domain/check"
	"github.com/CMedrado/VulnScan/domain/entities"
)

type Config struct {
	Path       string
	EnableXSS  bool
	EnableSQLi bool
	NewCheck   string
}

func ScanFile(cfg Config) ([]entities.Finding, error) {
	data, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, err
	}

	file := entities.File{
		Content: string(data),
		Name:    cfg.Path,
	}

	var findings []entities.Finding
	if cfg.EnableXSS {
		findings = append(findings, check.RunCheck(file, check.XSSCheck)...)
	}

	if cfg.EnableSQLi {
		findings = append(findings, check.RunCheck(file, check.SQLICheck)...)
	}

	if cfg.NewCheck != "" {
		parts := strings.Split(cfg.NewCheck, ",")
		if len(parts) >= 2 {
			checks := entities.Check{
				Name:              "Custom Check",
				RegularExpression: parts[0],
				DocumentTypes:     parts[1:],
			}
			findings = append(findings, check.RunCheck(file, checks)...)
		}
	}

	return findings, nil
}

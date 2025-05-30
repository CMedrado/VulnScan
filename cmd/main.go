package main

import (
	"flag"
	"fmt"

	"github.com/CMedrado/VulnScan/app"
)

func main() {
	path := flag.String("path", "", "Path to the source code")
	xss := flag.Bool("xss", false, "Enable XSS check")
	sqli := flag.Bool("sqli", false, "Enable SQL Injection check")
	newCheck := flag.String("new_check", "", "{Regular expression, document type(s)}. Ex: `(?i)alert\\s*\\(.*?\\)`,php,html")

	flag.Parse()

	if *path == "" {
		fmt.Println("Please provide a valid path using --path")
		return
	}

	cfg := app.Config{
		Path:       *path,
		EnableXSS:  *xss,
		EnableSQLi: *sqli,
		NewCheck:   *newCheck,
	}

	results, err := app.ScanFile(cfg)
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	if len(results) == 0 {
		fmt.Println("✅ No vulnerabilities found!")
		return
	}

	for _, result := range results {
		fmt.Printf("🔴 [%s:%d] %s => Match: %s\n", result.Path, result.Line, result.NameCheck, result.Content)
	}
}

# 🛡️ VulnScan

A vulnerability scanner for source code written in Go, with clean architecture and support for custom rules.

---

## 🚀 How to Use

### 📦 Installation

Clone the repository:

```bash
git clone https://github.com/CMedrado/VulnScan.git
cd scanner-app
```

### ▶️ Run the Scanner

```bash
go run ./cmd/main.go --path=<FILE_PATH> [--xss] [--sqli] [--new_check="<REGEX>,<ext1>,<ext2>"]
```

#### Examples:

* **Check for XSS:**

```bash
go run ./cmd/main.go --path=test.html --xss
```

* **Check for SQL Injection:**

```bash
go run ./cmd/main.go --path=test.go --sqli
```

* **Use a custom rule:**

```bash
go run ./cmd/main.go --path=test.js --new_check="(?i)document\.write\s*\(.*?\),js,html"
```

---

## ✅ What It Detects

### 🔍 Built-in Rules

| Type          | Regex                                    | Supported Extensions |
| ------------- | ---------------------------------------- | -------------------- |
| XSS           | `(?i)alert\s*\([^)]*\)`                  | html, js             |
| SQL Injection | `(?si)\"[^\"]*?SELECT.*?WHERE.*?%s.*?\"` | all                  |

### ➕ Custom Rules

You can pass a regex + file types using the `--new_check` flag.

Example:

```bash
--new_check="(?i)console\.log\(.*?\),js"
```

---

## 🧪 Tests

To run the tests:

```bash
go test ./...
```

---

## 🧱 Architecture

* `cmd/main.go` → entrypoint
* `app` → use case (scan file)
* `domain/check` → business logic (checks)
* `domain/entity` → pure entities (File, Check, Finding)


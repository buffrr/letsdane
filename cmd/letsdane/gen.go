//go:build ignore
// +build ignore

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

//go:generate go run gen.go

func main() {
	source := "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	resp, err := http.Get(source)
	if err != nil {
		log.Fatalf("error requesting tld list: %v", err)
	}
	defer resp.Body.Close()
	var sb bytes.Buffer

	h := fmt.Sprintf(`// source: %s

var nameConstraints = map[string]struct{} {
`, source)

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line != "" && line[0] == '#' {
			sb.WriteString("package main\n\n")
			sb.WriteString("// auto generated do not edit\n")
			sb.WriteString("//" + line[1:] + "\n")
			sb.WriteString(h)
			continue
		}

		sb.WriteString(`	"`)
		sb.WriteString(line)
		sb.WriteRune('"')
		sb.WriteString(": {}, \n")
	}
	sb.WriteString("}\n")

	if err := os.WriteFile("tld.go", sb.Bytes(), 0600); err != nil {
		log.Fatal(err)
	}

}

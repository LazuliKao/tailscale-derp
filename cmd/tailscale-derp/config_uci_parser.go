//go:build uciconfig

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func parseUCIConfig(path string) (*uciConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	parsed := &uciConfig{values: make(map[string]map[string][]string)}
	scanner := bufio.NewScanner(file)
	currentSection := ""
	currentType := ""

	for lineNum := 1; scanner.Scan(); lineNum++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "config":
			if len(fields) < 2 {
				return nil, fmt.Errorf("invalid config declaration on line %d", lineNum)
			}
			currentType = trimQuotes(fields[1])
			currentSection = ""
			if len(fields) >= 3 {
				currentSection = trimQuotes(fields[2])
			}
			if currentSection == "" {
				for index := 1; ; index++ {
					candidate := fmt.Sprintf("%s_%d", currentType, index)
					if _, exists := parsed.values[candidate]; !exists {
						currentSection = candidate
						break
					}
				}
			}
			sectionValues := make(map[string][]string)
			parsed.values[currentSection] = sectionValues
			parsed.sections = append(parsed.sections, uciSection{typ: currentType, name: currentSection, values: sectionValues})
		case "option":
			if currentSection == "" || len(fields) < 3 {
				return nil, fmt.Errorf("invalid option declaration on line %d", lineNum)
			}
			key := trimQuotes(fields[1])
			value := trimQuotes(strings.Join(fields[2:], " "))
			parsed.values[currentSection][key] = []string{value}
		case "list":
			if currentSection == "" || len(fields) < 3 {
				return nil, fmt.Errorf("invalid list declaration on line %d", lineNum)
			}
			key := trimQuotes(fields[1])
			value := trimQuotes(strings.Join(fields[2:], " "))
			parsed.values[currentSection][key] = append(parsed.values[currentSection][key], value)
		default:
			return nil, fmt.Errorf("unsupported directive %q on line %d", fields[0], lineNum)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func trimQuotes(value string) string {
	return strings.Trim(value, "'\"")
}

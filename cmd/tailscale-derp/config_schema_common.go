package main

import "strings"

func schemaOutputPath(args []string) string {
	for index, arg := range args {
		if value, ok := strings.CutPrefix(arg, "--generate-config-schema="); ok {
			return value
		}
		if arg == "--generate-config-schema" && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}

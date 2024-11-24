package main

import (
	"os"
	"path/filepath"
	"strings"
)

func confName() string {
	base := filepath.Base(os.Args[0])
	if base == "" || base == "." || base == string(filepath.Separator) {
		panic("invalid argument")
	}
	if dot := strings.LastIndexByte(base, '.'); dot > 0 {
		return base[:dot] + ".toml"
	}
	return base + ".toml"
}

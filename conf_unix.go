//go:build !windows

package main

import (
	"os"
	"path/filepath"
)

func confName() string {
	base := filepath.Base(os.Args[0])
	if base == "" || base == "." || base == string(filepath.Separator) {
		panic("invalid argument")
	}
	return base + ".toml"
}

// Command vdt is a modular developer tools CLI.
package main

import (
	"fmt"
	"os"

	"github.com/viniciusfranca/vdt/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

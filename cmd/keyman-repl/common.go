package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func flagNew(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", name)

		fs.VisitAll(func(f *flag.Flag) {
			fmt.Printf("  --%s\n", f.Name)
			fmt.Printf("      %s\n", f.Usage)
		})
	}
	return fs
}

func generateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func mustDecodeHex(label string, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid hex for %s: %v\n", label, err)
		os.Exit(1)
	}
	return b
}

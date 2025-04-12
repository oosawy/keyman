package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/oosawy/keyman/internal/core/cipherkit"
)

var globalAesKey cipherkit.MasterKey

func main() {
	fmt.Println("keyman-repl: Type `help` to see available commands")

	var err error
	globalAesKey, err = generateAESKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate AES key: %v", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()

		parts := strings.Fields(line)
		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "help":
			printUsage()
		case "keygen":
			runKeygen(args)
		case "derive":
			runDerive(args)
		case "sign":
			runSign(args)
		case "verify":
			runVerify(args)
		case "fingerprint":
			runFingerprint(args)
		case "exit":
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		}

		fmt.Println()
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading stdin input: ", err)
	}
}

func printUsage() {
	fmt.Println(`Commands:
  keygen
      Generate a keypair (outputs: secret key, public key, fingerprint)

  derive --secret SECRET_KEY_HEX
      Derive public key and fingerprint from a secret key

  sign --secret SECRET_KEY_HEX --message MESSAGE
      Sign a message using the secret key

  verify --public PUBLIC_KEY_HEX --message MESSAGE --signature HEX
      Verify a signature using the public key

  fingerprint [--public PUBLIC_KEY_HEX] | [--secret SECRET_KEY_HEX]
      Compute fingerprint from a public key or secret key`)
}

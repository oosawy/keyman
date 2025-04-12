package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/rpc"
	"os"

	"github.com/oosawy/keyman/pkg/api"
)

var host = flag.String("host", "localhost:8222", "RPC server host")

func main() {
	flag.Parse()

	if len(os.Args) <= 2 {
		fmt.Println("Usage: keyman-client <keygen|derive|sign>")
		return
	}

	subcmd := os.Args[1]
	subargs := os.Args[2:]

	switch subcmd {
	case "keygen":
		client := dial()
		defer client.Close()
		runKeygen(client)
	case "derive":
		client := dial()
		defer client.Close()
		runDerive(client, subargs)
	case "sign":
		client := dial()
		defer client.Close()
		runSign(client, subargs)
	default:
		fmt.Println("Usage: keyman-client <keygen|derive|sign>")
		os.Exit(1)
	}

}

func dial() *rpc.Client {
	client, err := rpc.Dial("tcp", *host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to server: %v", err)
		os.Exit(1)
	}
	return client
}

func mustDecodeHex(label string, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid hex for %s: %v\n", label, err)
		os.Exit(1)
	}
	return b
}

// keygen
func runKeygen(client *rpc.Client) {
	args := &api.KeymanKernelArgs{}
	reply := &api.KeymanKernelReply{}

	err := client.Call("KeymanKernel.Keygen", args, reply)
	if err != nil {
		fmt.Fprintf(os.Stderr, "RPC call failed: %v", err)
		os.Exit(1)
	}

	fmt.Printf("secretKey:   %x\n", reply.SecretKey)
	fmt.Printf("publicKey:   %x\n", reply.PublicKey)
	fmt.Printf("fingerprint: %x\n", reply.Fingerprint)
}

// derive --secret SECRET_KEY_HEX
func runDerive(client *rpc.Client, subargs []string) {
	fs := flag.NewFlagSet("derive", flag.ExitOnError)
	secretHex := fs.String("secret", "", "Secret key (hex)")
	fs.Parse(subargs)

	if *secretHex == "" {
		fs.Usage()
		return
	}

	secretKey := mustDecodeHex("secret", *secretHex)

	args := &api.KeymanKernelDeriveArgs{SecretKey: secretKey}
	reply := &api.KeymanKernelDeriveReply{}

	err := client.Call("KeymanKernel.Derive", args, reply)
	if err != nil {
		fmt.Fprintf(os.Stderr, "RPC call failed: %v", err)
		os.Exit(1)
	}

	fmt.Printf("publicKey:   %x\n", reply.PublicKey)
	fmt.Printf("fingerprint: %x\n", reply.Fingerprint)
}

// sign --secret SECRET_KEY_HEX --message MESSAGE
func runSign(client *rpc.Client, subargs []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	secretHex := fs.String("secret", "", "Secret key (hex)")
	message := fs.String("message", "", "Message to sign")
	fs.Parse(subargs)

	if *secretHex == "" || *message == "" {
		fs.Usage()
		return
	}

	args := &api.KeymanKernelSignArgs{
		SecretKey: mustDecodeHex("secret", *secretHex),
		Message:   []byte(*message),
	}
	reply := &api.KeymanKernelSignReply{}

	err := client.Call("KeymanKernel.Sign", args, reply)
	if err != nil {
		fmt.Fprintf(os.Stderr, "RPC call failed: %v", err)
		os.Exit(1)
	}

	fmt.Printf("signature: %x\n", reply.Signature)
}

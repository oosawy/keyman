package main

import (
	"crypto/sha256"
	"log"
	"net"
	"net/rpc"
	"os"
)

func main() {
	kernel := &KeymanKernel{
		masterKey: loadMasterKey(),
	}

	err := rpc.Register(kernel)
	if err != nil {
		log.Fatal("Error registering Keyman kernel:", err)
	}

	port := os.Getenv("KEYMAN_PORT")
	if port == "" {
		port = "8222"
	}

	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal("Error starting TCP listener:", err)
	}
	defer l.Close()

	log.Println("RPC Server is listening on port", port)
	rpc.Accept(l)
}

func loadMasterKey() []byte {
	mk := os.Getenv("KEYMAN_MASTER_KEY")

	if mk == "" {
		log.Fatal("Master key is required")
	}

	b := []byte(mk)
	hash := sha256.Sum256(b)
	return hash[:]
}

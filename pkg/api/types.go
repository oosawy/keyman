package api

type KeymanKernelArgs struct {
}

type KeymanKernelReply struct {
	SecretKey   []byte
	PublicKey   []byte
	Fingerprint []byte
}

type KeymanKernelDeriveArgs struct {
	SecretKey []byte
}

type KeymanKernelDeriveReply struct {
	PublicKey   []byte
	Fingerprint []byte
}

type KeymanKernelSignArgs struct {
	SecretKey []byte
	Message   []byte
}

type KeymanKernelSignReply struct {
	Signature []byte
}

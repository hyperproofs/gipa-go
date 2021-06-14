package gipa

import (
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/utils"
)

// Given alpha, beta, G, H, this will return ck, A, and B.
func GenerateGipaInstance(m uint64, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) (*cm.Ck, []mcl.G1, []mcl.G2) {
	ck := cm.IPPSetup(m, alpha, beta, g, h)
	A, B := utils.GenerateData(m)
	return ck, A, B
}

// Run GenerateGipaInstance to get ck, A, and B. Using that create a prover and verifier.
func AssembleProverVerifier(m uint64, ck *cm.Ck, A []mcl.G1, B []mcl.G2) (Prover, Verifier) {

	Z := utils.InnerProd(A, B)
	com := cm.IPPCM(ck, A, B, Z)

	prover := Prover{}
	verifier := Verifier{}

	prover.Init(m, ck, A, B)
	verifier.Init(m, ck, com)
	return prover, verifier
}

// Calls the above two functions at once for simple ease. Nothing fancy.
func GipaTestSetup(m uint64, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) (Prover, Verifier) {
	ck, A, B := GenerateGipaInstance(m, alpha, beta, g, h)
	prover, verifier := AssembleProverVerifier(m, ck, A, B)
	return prover, verifier
}

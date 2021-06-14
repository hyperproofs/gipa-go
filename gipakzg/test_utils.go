package gipakzg

import (
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/utils"
	"github.com/hyperproofs/kzg-go/kzg"
)

// Given alpha, beta, G, H, this will return ck, A, and B.
func GenerateGipaKzgInstance(mn uint64, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) (*cm.Ck, *kzg.KZG1Settings, *kzg.KZG2Settings, []mcl.G1, []mcl.G2) {
	ck, kzg1, kzg2 := cm.IPPSetupKZG(mn, alpha, beta, g, h)
	A, B := utils.GenerateData(mn)
	return ck, kzg1, kzg2, A, B
}

// Run GenerateGipaKzgInstance to get ck, A, and B. Using that create a prover and verifier.
func AssembleProverVerifier(m uint64, ck *cm.Ck, kzg1 *kzg.KZG1Settings, kzg2 *kzg.KZG2Settings, A []mcl.G1, B []mcl.G2) (Prover, Verifier) {

	Z := utils.InnerProd(A, B)
	com := cm.IPPCM(ck, A, B, Z)

	prover := Prover{}
	verifier := Verifier{}

	prover.Init(m, ck, kzg1, kzg2, A, B)
	verifier.Init(m, kzg1, kzg2, com)
	return prover, verifier
}

// Calls the above two functions at once for simple ease. Nothing fancy.
func GipaKzgTestSetup(mn uint64, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) (Prover, Verifier) {
	ck, kzg1, kzg2, A, B := GenerateGipaKzgInstance(mn, alpha, beta, g, h)
	prover, verifier := AssembleProverVerifier(mn, ck, kzg1, kzg2, A, B)
	return prover, verifier
}

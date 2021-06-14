package batch

import (
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/utils"
	"github.com/hyperproofs/kzg-go/kzg"
)

// Given alpha, beta, G, H, this will return ck, A, and B.
func GenerateBatchInstance(m uint32, n uint32, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) (*cm.Ck, *kzg.KZG1Settings, *kzg.KZG2Settings, []mcl.G1, []mcl.G2, []mcl.G1, []mcl.G2) {
	mn := uint64(m * n)
	ck, kzg1, kzg2 := cm.IPPSetupKZG(mn, alpha, beta, g, h)
	P, Q, A, B := utils.GenerateBatchingData(m, n)
	return ck, kzg1, kzg2, P, Q, A, B
}

// Run GenerateBatchInstance to get ck, A, and B. Using that create a prover and verifier.
func AssembleProverVerifier(m uint32,
	ck *cm.Ck, kzg1 *kzg.KZG1Settings, kzg2 *kzg.KZG2Settings,
	P []mcl.G1, Q []mcl.G2,
	A []mcl.G1, B []mcl.G2) (Prover, Verifier) {

	mn := uint64(len(A))
	n := uint32(len(P))
	prover := Prover{}
	verifier := Verifier{}

	prover.Init(m, n, mn, ck, kzg1, kzg2, A, B)
	verifier.Init(m, n, mn, ck.W, kzg1, kzg2, P, Q, B)

	return prover, verifier
}

// Calls the above two functions at once for simple ease. Nothing fancy.
func GipaBatchTestSetup(m uint32, n uint32, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) (Prover, Verifier) {
	ck, kzg1, kzg2, P, Q, A, B := GenerateBatchInstance(m, n, alpha, beta, g, h)
	prover, verifier := AssembleProverVerifier(m, ck, kzg1, kzg2, P, Q, A, B)
	return prover, verifier
}

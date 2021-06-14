package batchplain

import (
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/utils"
)

// Given alpha, beta, G, H, this will return ck, A, and B.
func GenerateBatchPlainInstance(m uint32, n uint32, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) (*cm.Ck, []mcl.G1, []mcl.G2, []mcl.G1, []mcl.G2) {
	mn := uint64(m * n)
	ck := cm.IPPSetup(mn, alpha, beta, g, h)
	P, Q, A, B := utils.GenerateBatchingData(m, n)
	return ck, P, Q, A, B
}

// Run GenerateBatchPlainInstance to get ck, A, and B. Using that create a prover and verifier.
func AssembleProverVerifier(m uint32,
	ck *cm.Ck, P []mcl.G1, Q []mcl.G2,
	A []mcl.G1, B []mcl.G2) (Prover, Verifier) {

	mn := uint64(len(A))
	n := uint32(len(P))
	prover := Prover{}
	verifier := Verifier{}

	prover.Init(m, n, mn, ck, A, B)
	verifier.Init(m, n, mn, ck, P, Q, B)

	return prover, verifier
}

// Calls the above two functions at once for simple ease. Nothing fancy.
func GipaBatchPlainTestSetup(m uint32, n uint32, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) (Prover, Verifier) {
	ck, P, Q, A, B := GenerateBatchPlainInstance(m, n, alpha, beta, g, h)
	prover, verifier := AssembleProverVerifier(m, ck, P, Q, A, B)
	return prover, verifier
}

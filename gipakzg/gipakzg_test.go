package gipakzg

import (
	"fmt"
	"testing"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/gipa"
	"github.com/hyperproofs/gipa-go/utils"
)

func TestGIPAKZG(t *testing.T) {

	var status bool
	M := uint64(1) << 10
	alpha, beta, g, h := utils.RunMPC()
	prover, verifier := GipaKzgTestSetup(M, alpha, beta, g, h)
	ck, A, B := extract(&prover) // Create a copy
	proof := prover.Prove()
	status = verifier.Verify(proof)

	t.Run(fmt.Sprintf("%d/GIPA+KZG;", M), func(t *testing.T) {
		if status == false {
			t.Errorf("GIPAKZG Test: Failed")
		}
	})

	p, v := gipa.AssembleProverVerifier(M, &ck, A, B)
	proofGipa := p.Prove()
	status = v.Verify(proofGipa)

	t.Run(fmt.Sprintf("%d/GIPA;", M), func(t *testing.T) {
		if status == false {
			t.Errorf("KZG: GIPA also failed")
		}
	})

	t.Run(fmt.Sprintf("%d/ProofCompare;", M), func(t *testing.T) {
		status = CompareProofs(proof, proofGipa)
		if status == false {
			t.Errorf("Proof comparison failed")
		}
	})
}

func extract(prover *Prover) (cm.Ck, []mcl.G1, []mcl.G2) {

	ck := cm.Ck{}
	ck.Clone(&prover.Ck)
	A := make([]mcl.G1, ck.M)
	B := make([]mcl.G2, ck.M)

	copy(A, prover.A)
	copy(B, prover.B)
	return ck, A, B
}

func CompareProofs(piKZG Proof, pi gipa.Proof) bool {
	// L   []cm.Com  // Left commitments at each level
	// R   []cm.Com  // Right Commitments at each level
	// A   [1]mcl.G1 // Final value of A after log M rounds
	// B   [1]mcl.G2 // Final value of B after log M rounds

	if len(piKZG.L) != len(pi.L) {
		fmt.Println("Left commitments len did not match.")
		return false
	}
	if len(piKZG.R) != len(pi.R) {
		fmt.Println("Right commitments len did not match.")
		return false
	}

	for i := range piKZG.L {
		if piKZG.L[i].IsEqual(&pi.L[i]) == false {
			fmt.Printf("Left commitment len did not match at %d\n", i)
			return false
		}
	}
	for i := range piKZG.R {
		if !piKZG.R[i].IsEqual(&pi.R[i]) {
			fmt.Printf("Right commitment len did not match at %d\n", i)
			return false
		}
	}
	if piKZG.A[0].IsEqual(&pi.A[0]) == false {
		fmt.Printf("A[0] did not match\n")
		return false
	}
	if piKZG.B[0].IsEqual(&pi.B[0]) == false {
		fmt.Printf("B[0] did not match\n")
		return false
	}
	return true
}

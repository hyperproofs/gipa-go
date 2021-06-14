package gipakzg

import (
	"fmt"
	"testing"

	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/utils"
)

func testsetup() []uint8 {
	return []uint8{8, 9, 10, 11, 12, 13, 14, 15, 16, 17}
}

func BenchmarkGIPAKZG(b *testing.B) {

	folderPath := "../ck-19"
	rows := testsetup()
	A, B := utils.GenerateData(1 << (rows[len(rows)-1]))

	for _, ell := range rows {
		M := uint64(1) << ell
		ck, kzg1, kzg2 := cm.LoadKeys(M, folderPath)
		prover, verifier := AssembleProverVerifier(M, &ck, &kzg1, &kzg2, A[:M], B[:M])
		var proofs []Proof

		b.Run(fmt.Sprintf("%d/Prove;%d", ell, M), func(b *testing.B) {
			var proverLocal Prover
			for bn := 0; bn < b.N; bn++ {
				proverLocal = Prover{}
				proverLocal.Clone(&prover)
				b.StartTimer()
				proof := proverLocal.Prove()
				b.StopTimer()
				proofs = append(proofs, proof)
			}
		})

		b.Run(fmt.Sprintf("%d/Verifier;%d", ell, M), func(b *testing.B) {
			var verifierLocal Verifier
			var proof Proof
			var status bool
			for bn := 0; bn < b.N; bn++ {
				verifierLocal = Verifier{}
				verifierLocal.Clone(&verifier)
				proof, proofs = proofs[0], proofs[1:]
				b.StartTimer()
				status = verifierLocal.Verify(proof)
				b.StopTimer()
				if !status {
					b.Errorf("GIPA+KZG Verification failed")
				}
			}
		})
	}
}

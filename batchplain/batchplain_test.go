package batchplain

import (
	"fmt"
	"testing"

	"github.com/hyperproofs/gipa-go/utils"
	"github.com/jinzhu/copier"
)

func TestBatchingPlain(t *testing.T) {

	var status bool
	M := uint32(1) << 4
	N := uint32(1) << 7
	alpha, beta, g, h := utils.RunMPC()
	prover, verifier := GipaBatchPlainTestSetup(M, N, alpha, beta, g, h)
	proof := prover.Prove()
	var verifierCopy Verifier
	// verifierCopy.Clone(&verifier)
	copier.Copy(&verifierCopy, &verifier)
	status = verifier.Verify(proof)
	t.Run(fmt.Sprintf("%d/BatchingPlain;", M), func(t *testing.T) {
		if status == false {
			t.Errorf("BatchingPlain Test: Failed")
		}
	})

	status = verifierCopy.VerifyEdrax(proof)
	t.Run(fmt.Sprintf("%d/BatchingPlainEdrax;", M), func(t *testing.T) {
		if status == false {
			t.Errorf("BatchingPlain Test: Failed")
		}
	})
}

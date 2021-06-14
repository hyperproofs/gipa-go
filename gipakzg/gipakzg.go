package gipakzg

import (
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/utils"
	fft "github.com/hyperproofs/kzg-go/fft"
)

// "math/rand"

type Proof struct {
	L   []cm.Com  // Left commitments at each level
	R   []cm.Com  // Right Commitments at each level
	A   [1]mcl.G1 // Final value of A after log M rounds
	B   [1]mcl.G2 // Final value of B after log M rounds
	W   mcl.G1    // Left commitment key
	V   mcl.G2    // Right commitment key
	Pi1 mcl.G1    // Proof of correct evaluation of Halo poly W
	Pi2 mcl.G2    // Proof of correct evaluation of Halo poly V
}

func (self *Proof) Append(ComL cm.Com, ComR cm.Com) {
	self.L = append(self.L, ComL)
	self.R = append(self.R, ComR)
}

func (self *Proof) At(i uint64) (cm.Com, cm.Com) {
	return self.L[i], self.R[i]
}

func BuildHaloPoly(RandomChallenges []mcl.Fr, invert bool) []mcl.Fr {

	l := len(RandomChallenges)
	poly := make([][]mcl.Fr, l)
	for i := range poly {
		degree := uint64(1) << (i + 1)
		poly[i] = make([]mcl.Fr, degree+1) // Degree + 1 is the size of the array.
		poly[i][0].SetInt64(1)
		if invert == false {
			poly[i][degree] = RandomChallenges[l-i-1]
		} else {
			mcl.FrInv(&poly[i][degree], &RandomChallenges[l-i-1])
		}
	}
	f := poly[0]
	for i := 1; i < l; i++ {
		f = fft.PolyMul(f, poly[i])
	}
	return f
}

// Evaluate the halo poly at evaluationPoint.
func EvaluateHaloPoly(RandomChallenges []mcl.Fr, evaluationPoint mcl.Fr, invert bool) mcl.Fr {
	var result mcl.Fr
	var ONE mcl.Fr
	l := len(RandomChallenges)

	result.SetInt64(1)
	ONE.SetInt64(1)
	for i := 0; i < l; i++ {
		degree := int64(1) << (i + 1)
		var a, b mcl.Fr
		a = utils.FrPow(evaluationPoint, degree)

		if !invert {
			b = RandomChallenges[l-i-1]
		} else {
			mcl.FrInv(&b, &RandomChallenges[l-i-1])
		}

		mcl.FrMul(&b, &b, &a)
		mcl.FrAdd(&b, &b, &ONE)
		mcl.FrMul(&result, &result, &b)
	}
	return result
}

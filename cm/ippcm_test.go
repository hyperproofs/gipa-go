package cm

import (
	"fmt"
	"testing"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/utils"
	"github.com/hyperproofs/kzg-go/kzg"
)

func GenerateIppcmData(M uint64) (ck *Ck, alpha mcl.Fr, beta mcl.Fr, G mcl.G1, H mcl.G2, A []mcl.G1, B []mcl.G2, Z mcl.GT) {

	alpha, beta, G, H = utils.RunMPC()
	ck = IPPSetup(M, alpha, beta, G, H)

	A, B = utils.GenerateData(M)

	Z = utils.InnerProd(A, B)
	return ck, alpha, beta, G, H, A, B, Z
}

func GenerateIppcmKzgData(MN uint64) (ck *Ck, kzg1 *kzg.KZG1Settings, kzg2 *kzg.KZG2Settings, alpha mcl.Fr, beta mcl.Fr, G mcl.G1, H mcl.G2, A []mcl.G1, B []mcl.G2, Z mcl.GT) {

	alpha, beta, G, H = utils.RunMPC()
	ck, kzg1, kzg2 = IPPSetupKZG(MN, alpha, beta, G, H)
	A, B = utils.GenerateData(MN)

	Z = utils.InnerProd(A, B)
	return ck, kzg1, kzg2, alpha, beta, G, H, A, B, Z
}

func TestCm(t *testing.T) {
	mcl.InitFromString("bls12-381")

	L := 10
	M := uint64(1) << L
	ck, alpha, beta, G, H, A, B, Z := GenerateIppcmData(M)

	t.Run(fmt.Sprintf("%d/CheckCK;", M), func(t *testing.T) {
		var a, r mcl.Fr
		a.SetInt64(1)
		mcl.FrSqr(&r, &alpha)
		exponent := SumGeomProgression(M, a, r)

		var aLHS mcl.G1
		mcl.G1Mul(&aLHS, &G, &exponent)

		var aSum mcl.G1
		aSum.SetString("0", 10)
		for i := 0; i < len(ck.W); i++ {
			mcl.G1Add(&aSum, &aSum, &ck.W[i])
		}

		if aSum.IsEqual(&aLHS) == false {
			t.Errorf("Alpha: Verification Failed")
		}

		mcl.FrSqr(&r, &beta)
		exponent = SumGeomProgression(M, a, r)
		var bLHS mcl.G2
		mcl.G2Mul(&bLHS, &H, &exponent)

		var bSum mcl.G2
		bSum.SetString("0", 10)
		for i := 0; i < len(ck.V); i++ {
			mcl.G2Add(&bSum, &bSum, &ck.V[i])
		}

		if bSum.IsEqual(&bLHS) == false {
			t.Errorf("Beta: Verification Failed")
		}
	})

	com := IPPCM(ck, A, B, Z)

	t.Run(fmt.Sprintf("%d/CheckCommitment;", M), func(t *testing.T) {

		var e1 mcl.GT
		mcl.MillerLoopVec(&e1, A, ck.V)
		mcl.FinalExp(&e1, &e1)
		if !e1.IsEqual(&com.Com[0]) {
			t.Errorf("Commitment: Part A failed.")
		}

		mcl.MillerLoopVec(&e1, ck.W, B)
		mcl.FinalExp(&e1, &e1)
		if !e1.IsEqual(&com.Com[1]) {
			t.Errorf("Commitment: Part B failed.")
		}

	})

	t.Run(fmt.Sprintf("%d/CkFold;", M), func(t *testing.T) {
		var x, xInv mcl.Fr
		x.Random()
		mcl.FrInv(&xInv, &x)

		ckPrime := Ck{}
		CkFold(&ckPrime, x, xInv, ck)

		if ck.M != M {
			t.Errorf("Ck Fold: Size of Ck changed!")
		}

		if ck.M != 2*ckPrime.M {
			t.Errorf("Ck Fold: CkPrime size is not expected!")
		}

		if len((ckPrime).V) != int(ckPrime.M) {
			t.Errorf("Ck Fold: CkPrime V is not same size!")
		}
		if len((ckPrime).W) != int(ckPrime.M) {
			t.Errorf("Ck Fold: CkPrime V is not same size!")
		}
	})
}

func TestCmKzg(t *testing.T) {
	mcl.InitFromString("bls12-381")

	// M := 10
	// N := 10
	MN := uint64(1024)
	// ck, kzg1, kzg2, alpha, beta, G, H, A, B, Z := GenerateIppcmKzgData(MN)
	ck, kzg1, kzg2, alpha, beta, G, H, _, _, _ := GenerateIppcmKzgData(MN)

	t.Run(fmt.Sprintf("%d/CheckCK;", MN), func(t *testing.T) {
		var a, r mcl.Fr
		a.SetInt64(1)
		mcl.FrSqr(&r, &alpha)
		exponent := SumGeomProgression(MN, a, r)

		var aLHS mcl.G1
		mcl.G1Mul(&aLHS, &G, &exponent)

		var aSum mcl.G1
		aSum.SetString("0", 10)
		for i := 0; i < len(ck.W); i++ {
			mcl.G1Add(&aSum, &aSum, &ck.W[i])
		}

		if aSum.IsEqual(&aLHS) == false {
			t.Errorf("Alpha: Verification Failed")
		}

		mcl.FrSqr(&r, &beta)
		exponent = SumGeomProgression(MN, a, r)
		var bLHS mcl.G2
		mcl.G2Mul(&bLHS, &H, &exponent)

		var bSum mcl.G2
		bSum.SetString("0", 10)
		for i := 0; i < len(ck.V); i++ {
			mcl.G2Add(&bSum, &bSum, &ck.V[i])
		}

		if bSum.IsEqual(&bLHS) == false {
			t.Errorf("Beta: Verification Failed")
		}
	})

	t.Run(fmt.Sprintf("%d/CheckKZGPK;", MN), func(t *testing.T) {
		var a, r mcl.Fr
		a.SetInt64(1)
		r = alpha
		exponent := SumGeomProgression(2*MN-1, a, r)

		var aLHS mcl.G1
		mcl.G1Mul(&aLHS, &G, &exponent)

		var aSum mcl.G1
		aSum.SetString("0", 10)
		for i := 0; i < len(kzg1.PK); i++ {
			mcl.G1Add(&aSum, &aSum, &kzg1.PK[i])
		}

		if aSum.IsEqual(&aLHS) == false {
			t.Errorf("KZG1 PK: Verification Failed")
		}

		r = beta
		exponent = SumGeomProgression(2*MN-1, a, r)
		var bLHS mcl.G2
		mcl.G2Mul(&bLHS, &H, &exponent)

		var bSum mcl.G2
		bSum.SetString("0", 10)
		for i := 0; i < len(kzg2.PK); i++ {
			mcl.G2Add(&bSum, &bSum, &kzg2.PK[i])
		}

		if bSum.IsEqual(&bLHS) == false {
			t.Errorf("KZG2 PK: Verification Failed")
		}
	})

}

// a(1 - r^n)/(1 - r)
func SumGeomProgression(n uint64, a mcl.Fr, r mcl.Fr) mcl.Fr {
	var result, num, denom mcl.Fr
	var ONE mcl.Fr
	ONE.SetInt64(1)

	result = utils.FrPow(r, int64(n))
	mcl.FrSub(&num, &ONE, &result)
	mcl.FrMul(&result, &num, &a)
	mcl.FrSub(&denom, &ONE, &r)
	mcl.FrDiv(&result, &result, &denom)
	return result
}

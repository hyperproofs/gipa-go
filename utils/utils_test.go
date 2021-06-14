package utils

import (
	"testing"

	"github.com/alinush/go-mcl"
)

func TestValidM1(t *testing.T) {

	status := IsPow2(10)
	if status == true {
		t.Errorf("Want false")
	}
}

func TestValidM(t *testing.T) {
	var tests = []struct {
		input uint64
		want  bool
	}{
		{1 << 63, true},
		{1<<63 - 1, false},
	}
	for _, tt := range tests {
		// testname := fmt.Sprintf("%d", tt.input)
		// t.Run(testname, func(t *testing.T) {
		ans := IsPow2(tt.input)
		if ans != tt.want {
			t.Errorf("%d: got %t want %t", tt.input, ans, tt.want)
		}
		// })
	}
}

func TestInnerProd(t *testing.T) {

	N := 20
	var P mcl.G1
	var P_i mcl.G1
	var Q mcl.G2
	var PVec []mcl.G1
	var QVec []mcl.G2

	Q.Random()
	for i := 0; i < N; i++ {
		P_i.Random()
		PVec = append(PVec, P_i)
		mcl.G1Add(&P, &P, &P_i)
		QVec = append(QVec, Q)
	}

	var want mcl.GT
	mcl.Pairing(&want, &P, &Q)
	got := InnerProd(PVec, QVec)

	if got.IsEqual(&want) == false {
		t.Errorf("Inner Prod Unequal")
	}
}

func TestFrPow(t *testing.T) {
	N := 20
	var alpha mcl.Fr
	alpha.Random()

	var a, b mcl.Fr
	mcl.FrInv(&a, &alpha)
	b = FrPow(alpha, -1)
	if !a.IsEqual(&b) {
		t.Errorf("FrPow: Neg Index Failed")
	}

	a.SetInt64(1)
	for i := 0; i < N; i++ {
		b = FrPow(alpha, int64(i))
		if !a.IsEqual(&b) {
			t.Errorf("FrPow: Failed at %d", i)
		}
		mcl.FrMul(&a, &a, &alpha)
	}
}

func TestFold(t *testing.T) {
	N := uint64(1) << 10
	var x mcl.Fr
	x.Random()
	var G1, G2, G []mcl.G1
	var H1, H2, H []mcl.G2

	G1 = make([]mcl.G1, N)
	G2 = make([]mcl.G1, N)
	G = make([]mcl.G1, N)

	for i := 0; i < len(G1); i++ {
		G2[i].Random()
		mcl.G1Mul(&G1[i], &G2[i], &x)
		mcl.G1Add(&G[i], &G1[i], &G2[i])
	}

	H1 = make([]mcl.G2, N)
	H2 = make([]mcl.G2, N)
	H = make([]mcl.G2, N)

	for i := 0; i < len(H1); i++ {
		H2[i].Random()
		mcl.G2Mul(&H1[i], &H2[i], &x)
		mcl.G2Add(&H[i], &H1[i], &H2[i])
	}

	resultG := G1Fold(x, G2, G2)
	resultH := G2Fold(x, H2, H2)

	if !G1SliceIsEqual(resultG, G) {
		t.Errorf("Slice G did not match after fold")
	}
	if !G2SliceIsEqual(resultH, H) {
		t.Errorf("Slice H did not match after fold")
	}
}

func TestBatchingData(t *testing.T) {

	P, Q, A, B := GenerateBatchingData(12, 300)
	var lhs, rhs mcl.GT
	mcl.MillerLoopVec(&lhs, P, Q)
	mcl.FinalExp(&lhs, &lhs)
	mcl.MillerLoopVec(&rhs, A, B)
	mcl.FinalExp(&rhs, &rhs)

	if lhs.IsEqual(&rhs) == false {
		t.Errorf("Batching data generator is an issue.")
	}
}

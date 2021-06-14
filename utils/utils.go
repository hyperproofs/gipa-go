package utils

import (
	"fmt"
	"math"
	"math/bits"

	"github.com/alinush/go-mcl"
)

// Find the nextpow of 2 >= input, expect for 0.
func NextPowOf2(v uint64) uint64 {
	if v == 0 {
		return 1
	}
	return uint64(1) << bits.Len64(v-1)
}

// ValidM checks if the input is a power of 2
func IsPow2(m uint64) bool {
	flag := m & (m - 1)
	if m > 0 && flag == 0 {
		return true // It is a power of two
	} else {
		return false // NOT a power of two
	}
}

// InnerProd computes the inner product of vector A and vector B
func InnerProd(A []mcl.G1, B []mcl.G2) mcl.GT {

	m := len(A)
	if m != len(B) || m < 1 {
		// Error handling
		panic(fmt.Sprintf("InnerProd: Error %d %d", m, len(B)))
	}

	var prod mcl.GT
	prod.SetInt64(1)
	mcl.MillerLoopVec(&prod, A, B)
	mcl.FinalExp(&prod, &prod)

	return prod
}

func MinUint64(a uint64, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func GetFrByteSize() int {
	return 32
	// return mcl.GetFrByteSize()
}

func GetG1ByteSize() int {
	return 48
	// return mcl.GetG1ByteSize()
}

func GetG2ByteSize() int {
	return 96
	// return mcl.GetG1ByteSize()
}

func GetGTByteSize() int {
	return 576
}

// Computes the a^x, where a is mcl.Fr and x is int64
func FrPow(a mcl.Fr, n int64) mcl.Fr { // n has to be signed

	var x, y mcl.Fr
	x = a

	if n == 0 {
		x.SetInt64(1)
		return x
	}

	if n < 0 {
		mcl.FrInv(&x, &x)
		n = -n
	}

	y.SetInt64(1)
	for n > 1 {
		if n%2 == 0 {
			mcl.FrSqr(&x, &x)
			n = n / 2
		} else {
			mcl.FrMul(&y, &x, &y)
			mcl.FrSqr(&x, &x)
			n = (n - 1) / 2
		}
	}
	mcl.FrMul(&y, &x, &y)
	return y
}

// Returns alpha, beta, G, H
func RunMPC() (mcl.Fr, mcl.Fr, mcl.G1, mcl.G2) {
	var alpha mcl.Fr
	var beta mcl.Fr
	var G mcl.G1
	var H mcl.G2

	alpha.Random()
	beta.Random()
	G.Random()
	H.Random()

	return alpha, beta, G, H
}

func GenerateData(m uint64) ([]mcl.G1, []mcl.G2) {

	A := make([]mcl.G1, m)
	B := make([]mcl.G2, m)

	for i := uint64(0); i < m; i++ {
		A[i].Random()
		B[i].Random()
	}
	return A, B
}

// e(P_i, Q_i) = e(A_i, B_i)...e(A_m, B_m)
// This will keep Q_i's  and B_i's the same
// This will allows us to test both batch.Verify and batch.VerifyEdrax
func GenerateBatchingData(m uint32, n uint32) ([]mcl.G1, []mcl.G2, []mcl.G1, []mcl.G2) {

	var P []mcl.G1
	var Q []mcl.G2
	var A []mcl.G1
	var B []mcl.G2

	var b mcl.G2
	b.Random()

	var a mcl.G1
	for j := uint32(0); j < n; j++ {

		var aSum mcl.G1
		for i := uint32(0); i < m; i++ {
			a.Random()
			A = append(A, a)
			B = append(B, b)
			mcl.G1Add(&aSum, &aSum, &a)
		}
		P = append(P, aSum)
		Q = append(Q, b)
	}
	return P, Q, A, B
}

// Check if anywhere we are dealing with instance size which not a power of 2.
// Works with Init()
// Of course, someone can directly change M or any exported parameters of any argument system.
func InstanceSizeChecker(M uint64, msg string) {
	if M < 1 || !IsPow2(M) {
		panic(msg)
	}
}

func SizeMismatchCheck(a, b uint64, msg string) {
	if a != b {
		panic(fmt.Sprintf("%s: One is %d, but other one is %d", msg, a, b))
	}
}

func ComputePadding(M, N uint32) (uint64, uint64) {
	MN := NextPowOf2(uint64(N * M))
	nDiff := uint64(uint64(math.Ceil(float64(MN)/float64(M))) - uint64(N)) // This is the size of padding for P and Q vector (gipa)
	mnDiff := uint64(MN - uint64((M * N)))                                 // This is the size of padding for A and B vector (gipa)
	return nDiff, mnDiff
}

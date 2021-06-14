package utils

import (
	"fmt"

	"github.com/alinush/go-mcl"
)

func G1SliceIsEqual(a, b []mcl.G1) bool {
	var status bool
	if len(a) != len(b) {
		return false
	}
	status = true
	for i := 0; i < len(a); i++ {
		status = status && a[i].IsEqual(&b[i])
		if !status {
			fmt.Printf("Failed at %d index out of %d\n", i, len(a)-1)
			return status
		}
	}
	return true
}

func G2SliceIsEqual(a, b []mcl.G2) bool {
	var status bool
	if len(a) != len(b) {
		return false
	}
	status = true
	for i := 0; i < len(a); i++ {
		status = status && a[i].IsEqual(&b[i])
		if !status {
			fmt.Printf("Failed at %d index out of %d\n", i, len(a)-1)
			return status
		}
	}
	return true
}

// G1Fold performs element wise: result = x * vec1 + vec2
// Ex: result[0] = x * vec1[0] + vec2[0]
// vec1 and vec2 has to be same size
// Parameters
// ----------
// result: G1 slice where the results are stored
// x : Fr, the exponent
// vec1: slice of mcl.G1
// vec2: slice of mcl.G1
// Returns
// -------
func G1Fold(x mcl.Fr, vec1 []mcl.G1, vec2 []mcl.G1) []mcl.G1 {
	// Vec1^x . Vec2
	// var result []mcl.G1
	m := len(vec1)
	if m != len(vec2) {
		panic("G1: Fold: Error")
	}

	result := make([]mcl.G1, m)

	for i := range vec1 {
		var temp mcl.G1
		mcl.G1Mul(&temp, &vec1[i], &x)
		mcl.G1Add(&result[i], &temp, &vec2[i])
	}
	return result
}

// G2Fold performs element wise: result = x * vec1 + vec2
// Ex: result[0] = x * vec1[0] + vec2[0]
// vec1 and vec2 has to be same size
// Parameters
// ----------
// result: G2 slice where the results are stored
// x : Fr, the exponent
// vec1: slice of mcl.G2
// vec2: slice of mcl.G2
// Returns
// -------
// None. Call by reference, thus output is stored in variable result
func G2Fold(x mcl.Fr, vec1 []mcl.G2, vec2 []mcl.G2) []mcl.G2 {
	// Not sure why call by reference did not work. Hence returning explicitly.
	// Vec1^x . Vec2
	// var result []mcl.G2
	m := len(vec1)
	if m != len(vec2) {
		// Error handling
		panic("G2: Fold: Error")
	}
	result := make([]mcl.G2, m)

	for i := range vec1 {
		var temp mcl.G2
		mcl.G2Mul(&temp, &vec1[i], &x)
		mcl.G2Add(&result[i], &temp, &vec2[i])
	}
	return result
}

// // Add the randomness to the vector
// // a_0, a_1, a_2, a_3, a_4, a_5will become
// // a_0, a_1, a_2^r, a_3^r, a_4^{r^2}, a_5^{r^2}.
func G1VecRandExpo(A []mcl.G1, r mcl.Fr, m int) []mcl.G1 {

	length := len(A)
	B := make([]mcl.G1, length)
	var base mcl.Fr
	var step mcl.Fr
	base.SetInt64(1)
	mcl.FrSqr(&step, &r)

	for i := m; i < length; i++ {
		if i%m == 0 {
			mcl.FrMul(&base, &base, &step)
		}
		mcl.G1Mul(&B[i], &A[i], &base)
	}
	return B
}

// // Add the randomness to the vector
// // a_0, a_1, a_2, a_3, a_4, a_5will become
// // a_0, a_1, a_2^r, a_3^r, a_4^{r^2}, a_5^{r^2}.
func G2VecRandExpo(A []mcl.G2, r mcl.Fr, m int) []mcl.G2 {

	length := len(A)
	B := make([]mcl.G2, length)
	var base mcl.Fr
	var step mcl.Fr
	base.SetInt64(1)
	mcl.FrSqr(&step, &r)

	for i := m; i < length; i++ {
		if i%m == 0 {
			mcl.FrMul(&base, &base, &step)
		}
		mcl.G2Mul(&B[i], &A[i], &base)
	}
	return B
}

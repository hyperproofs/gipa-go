package utils

import (
	"fmt"
	"testing"

	"github.com/alinush/go-mcl"
)

func BenchmarkUtilsInnerProd(b *testing.B) {

	N := 1 << 12
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

	var tests = []struct {
		A []mcl.G1
		B []mcl.G2
	}{
		{PVec, QVec},
	}
	b.ResetTimer()
	for z := 0; z < b.N; z++ {
		for i, tt := range tests {
			testname := fmt.Sprintf("%d-%d", i, N)
			b.Run(testname, func(b *testing.B) {
				e1 := InnerProd(tt.A, tt.B)
				b.StopTimer()
				var e2 mcl.GT
				mcl.Pairing(&e2, &P, &Q)
				if !e1.IsEqual(&e2) {
					b.Errorf("Pairing check did not match")
				}
				b.StartTimer()
			})
		}
	}
}

func BenchmarkUtilsValidM(b *testing.B) {

	var tests = []struct {
		input uint64
		want  bool
	}{
		{1 << 12, true},
		{1<<12 - 1, false},
	}
	for z := 0; z < b.N; z++ {
		for _, tt := range tests {
			testname := fmt.Sprintf("%d", tt.input)
			b.Run(testname, func(b *testing.B) {
				ans := IsPow2(tt.input)
				if ans != tt.want {
					b.Errorf("%d: got %t want %t", tt.input, ans, tt.want)
				}
			})
		}
	}
}

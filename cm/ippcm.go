package cm

import (
	"fmt"
	"sync"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/utils"
	"github.com/hyperproofs/kzg-go/kzg"
)

// Ck is a struct to hold LMR19 commitment keys.
// Note: Since ck_3 is 1_{\F_p}, it is ignored
type Ck struct {
	M uint64
	V []mcl.G2 // Ck_1
	W []mcl.G1 // Ck_2
}

// Com is a struct to hold AFGHO16 commitments.
// This hold the commitment decribed in Page 14 of https://eprint.iacr.org/2019/1177/20200212:182642
// com[0] holds the inner product of vector A and ck_1 aka \textbf{v}
// com[1] holds the inner product of vector B and ck_2 aka \textbf{w}
// com[2] holds the inner product of vector A and B
type Com struct {
	Com [3]mcl.GT
}

// Build powers of two as commitment keys for GIPA
// g^({\alpha}^{i})
// Send \alpha^2 or \alpha accordingly
func fillRange(ck *Ck, start uint64, stop uint64, alphaStep mcl.Fr, betaStep mcl.Fr, g mcl.G1, h mcl.G2, wg *sync.WaitGroup) {

	a := utils.FrPow(alphaStep, int64(start))
	b := utils.FrPow(betaStep, int64(start))

	for i := start; i < stop; i++ {
		mcl.G1Mul(&ck.W[i], &g, &a)
		mcl.G2Mul(&ck.V[i], &h, &b)
		mcl.FrMul(&a, &a, &alphaStep)
		mcl.FrMul(&b, &b, &betaStep)
	}
	wg.Done()
}

func fillRangeDriver(ubound uint64, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) *Ck {

	ck := Ck{ubound, make([]mcl.G2, ubound), make([]mcl.G1, ubound)}
	step := ubound / 8 // Dividing the workload for EIGHT cores
	if step < 1 {
		step = 1
	}

	start := uint64(0)
	stop := start + step
	stop = utils.MinUint64(stop, ubound)
	var wg sync.WaitGroup
	for start < ubound {
		wg.Add(1)
		go fillRange(&ck, start, stop, alpha, beta, g, h, &wg)
		start += step
		stop += step
		stop = utils.MinUint64(stop, ubound)
	}
	wg.Wait()
	return &ck
}

// Computes the commitment keys V and W
// Squares the alpha and beta while generating the commitment keys
func IPPSetup(m uint64, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) *Ck {

	var alphaSrq, betaSrq mcl.Fr
	mcl.FrSqr(&alphaSrq, &alpha)
	mcl.FrSqr(&betaSrq, &beta)

	if !utils.IsPow2(m) {
		panic("IPPPSetup: Not a power of two")
	}

	ck := fillRangeDriver(m, alphaSrq, betaSrq, g, h)
	return ck
}

// Commit function
// Computes result = (A * ck.V, ck.W * B, Z)
// Z is returned as is.
func IPPCM(ck *Ck, A []mcl.G1, B []mcl.G2, Z mcl.GT) Com {

	if !utils.IsPow2(ck.M) {
		//Error Handling
		panic(fmt.Sprintf("IPPCM: Error: Invalid M: %d", ck.M))
	}

	if ck.M != uint64(len(A)) {
		//Error Handling
		panic(fmt.Sprintf("IPPCM: Error: Size of A does not match: %d %d", ck.M, uint64(len(A))))
	}

	if ck.M != uint64(len(B)) {
		//Error Handling
		panic(fmt.Sprintf("IPPCM: Error: Size of B does not match: %d %d", ck.M, uint64(len(B))))
	}

	var com [3]mcl.GT
	com[0] = utils.InnerProd(A, ck.V)
	com[1] = utils.InnerProd(ck.W, B)
	com[2] = Z

	result := Com{com}
	return result
}

// G will be the Pk for KZG1
// H will be the Pk for KZG2
type KZGPk struct {
	G []mcl.G1
	H []mcl.G2
}

type KZGVk struct {
	G []mcl.G1
	H []mcl.G2
}

// Computes the keys of size 2mn - 1
// Computes the commitment keys V and W
// ck *Ck, kzg1 *kzg.KZG1Settings, kzg2 *kzg.KZG2Settings,
func IPPSetupKZG(mn uint64, alpha mcl.Fr, beta mcl.Fr, g mcl.G1, h mcl.G2) (*Ck, *kzg.KZG1Settings, *kzg.KZG2Settings) {

	if !utils.IsPow2(mn) {
		panic("GIPA+KZG: IPPPSetup: Not a power of two")
	}

	ubound := 2*mn - 1
	pk := KZGPk{
		make([]mcl.G1, ubound),
		make([]mcl.G2, ubound),
	}
	vk := KZGVk{
		make([]mcl.G1, 2),
		make([]mcl.G2, 2),
	}

	// Assign VK
	vk.G[0] = g
	vk.H[0] = h

	mcl.G1Mul(&vk.G[1], &vk.G[0], &beta)
	mcl.G2Mul(&vk.H[1], &vk.H[0], &alpha)

	// Assign PK

	var a mcl.G1
	var b mcl.G2
	mcl.G1Mul(&a, &g, &alpha)
	mcl.G2Mul(&b, &h, &beta)

	pk.G[0] = g
	pk.H[0] = h

	ckTemp := fillRangeDriver(ubound, alpha, beta, g, h)

	copy(pk.G, ckTemp.W)
	copy(pk.H, ckTemp.V)
	kzg1 := kzg.NewKZG1Settings(pk.G, vk.H)
	kzg2 := kzg.NewKZG2Settings(pk.H, vk.G)

	ck := Ck{mn, make([]mcl.G2, mn), make([]mcl.G1, mn)}
	for i := uint64(0); i < mn; i++ {
		ck.W[i] = pk.G[2*i]
		ck.V[i] = pk.H[2*i]
	}
	return &ck, kzg1, kzg2
}

// CkFold computes the new Ck for the next level of recursion.
// Given ck.V_L, ck.V_R, ck.W_L, ck.W_R computes ck' = (V', W') as follows:
// V' = xInv * V_R + V_L
// W' = x * W_R + W_L
// Parameters
// ----------
// result: Pointer to Ck type.
// x : Fr, the exponent
// xInv : Fr, the exponent. x and xInv should be inverse of each other.
// ck: pointer to Ck object.
//
// Returns
// -------
// None. Call by reference, thus output is stored in variable result
func CkFold(result *Ck, x mcl.Fr, xInv mcl.Fr, ck *Ck) {

	MPrime := ck.M / 2
	V_L := ck.V[:MPrime]
	V_R := ck.V[MPrime:]
	W_L := ck.W[:MPrime]
	W_R := ck.W[MPrime:]

	*result = Ck{}
	result.M = MPrime
	result.V = utils.G2Fold(xInv, V_R, V_L)
	result.W = utils.G1Fold(x, W_R, W_L)
	// return result
}

// ComFold computes the new commitment for the next level of recursion.
// Given com, ComL, ComR computes com' = ComL^x * com * ComR^(x^-1)
//
// Parameters
// ----------
// result: Pointer to Com type.
// x : Fr, the exponent
// xInv : Fr, the exponent. x and xInv should be inverse of each other.
// ComL: Pointer to Com type.
// com: Pointer to Com type.
// ComR: Pointer to Com type.
//
// Returns
// -------
// None. Call by reference, thus output is stored in variable result
func ComFold(x mcl.Fr, xInv mcl.Fr, ComL *Com, C *Com, ComR *Com) Com {
	result := Com{}
	var tempL, tempR mcl.GT

	mcl.GTPow(&tempL, &ComL.Com[0], &x)
	mcl.GTPow(&tempR, &ComR.Com[0], &xInv)
	mcl.GTMul(&result.Com[0], &tempL, &C.Com[0])
	mcl.GTMul(&result.Com[0], &result.Com[0], &tempR)

	mcl.GTPow(&tempL, &ComL.Com[1], &x)
	mcl.GTPow(&tempR, &ComR.Com[1], &xInv)
	mcl.GTMul(&result.Com[1], &tempL, &C.Com[1])
	mcl.GTMul(&result.Com[1], &result.Com[1], &tempR)

	mcl.GTPow(&tempL, &ComL.Com[2], &x)
	mcl.GTPow(&tempR, &ComR.Com[2], &xInv)
	mcl.GTMul(&result.Com[2], &tempL, &C.Com[2])
	mcl.GTMul(&result.Com[2], &result.Com[2], &tempR)

	return result
}

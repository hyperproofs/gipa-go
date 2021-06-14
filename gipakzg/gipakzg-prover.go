package gipakzg

import (
	"math/bits"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/utils"
	"github.com/hyperproofs/kzg-go/kzg"
	"golang.org/x/crypto/blake2b"
)

// Prover is a struct to manage the prover state.
type Prover struct {
	M  uint64
	A  []mcl.G1
	B  []mcl.G2
	Ck cm.Ck

	MPrime uint64
	A_L    []mcl.G1
	A_R    []mcl.G1
	B_L    []mcl.G2
	B_R    []mcl.G2
	Z_L    mcl.GT
	Z_R    mcl.GT
	Ck1    cm.Ck
	Ck2    cm.Ck

	ComL cm.Com
	ComR cm.Com
	X    []mcl.Fr

	KZG1 kzg.KZG1Settings
	KZG2 kzg.KZG2Settings

	Transcript       [32]byte
	RandomChallenges []mcl.Fr
}

// Transform is a member function of Prover
// It performs the following operations:
// - Breaks the vector A into two equal parts (A_L, A_R)
// - Breaks the vector B into two equal parts (B_L, B_R)
// - Computes z_L, z_R
// - Breaks the commitment key into half
// - Computes the left and right commitment
// Parameters
// ----------
// None
//
// Returns
// -------
// Updates the data members ComL and ComR.
// Returns ComL, ComR so that verifier can pose the challenge
func (self *Prover) Transform() (cm.Com, cm.Com) {
	MPrime := self.M / 2
	self.MPrime = MPrime
	self.A_L = self.A[:MPrime]
	self.A_R = self.A[MPrime:]
	self.B_L = self.B[:MPrime]
	self.B_R = self.B[MPrime:]

	self.Z_L = utils.InnerProd(self.A_R, self.B_L)
	self.Z_R = utils.InnerProd(self.A_L, self.B_R)

	self.Ck.Transform(&self.Ck1, &self.Ck2)
	self.ComL = cm.IPPCM(&self.Ck1, self.A_R, self.B_L, self.Z_L)
	self.ComR = cm.IPPCM(&self.Ck2, self.A_L, self.B_R, self.Z_R)

	return self.ComL, self.ComR
}

// Fold is a member function of Prover
// It computes:
// - A', B'
// - ck'
// Parameters
// ----------
// x, Fr the random challenge posed by the verifier
//
// Returns
// -------
// None
// Updates the data members A, B, and ck.
func (self *Prover) Fold(x mcl.Fr) {

	var y mcl.Fr
	mcl.FrInv(&y, &x)

	self.X = append(self.X, x)
	self.A = utils.G1Fold(x, self.A_R, self.A_L)
	self.B = utils.G2Fold(y, self.B_R, self.B_L)

	cm.CkFold(&self.Ck, x, y, &self.Ck)
	self.M = self.MPrime
}

func (self *Prover) FiatShamir() mcl.Fr {
	var x mcl.Fr
	// // H(Transcript, self.ComL, self.ComR)
	data := make([]byte, 0)
	data = append(data, self.Transcript[:]...)
	data = append(data, self.ComL.Com[0].Serialize()...)
	data = append(data, self.ComL.Com[1].Serialize()...)
	data = append(data, self.ComL.Com[2].Serialize()...)
	data = append(data, self.ComR.Com[0].Serialize()...)
	data = append(data, self.ComR.Com[1].Serialize()...)
	data = append(data, self.ComR.Com[2].Serialize()...)
	hash := blake2b.Sum256(data)
	copy(self.Transcript[:], hash[:])
	x.SetHashOf(hash[:])
	return x
}

// func (self *Prover) Prove_(A []mcl.G1, B []mcl.G2) Proof {
// 	self.A = make([]mcl.G1, self.M)
// 	self.B = make([]mcl.G2, self.M)
// 	copy(self.A, A)
// 	copy(self.B, B)
// 	proof := self.Prove()
// 	return proof
// }

func (self *Prover) Prove() Proof {
	var proof Proof
	// proofSize := uint32(math.Ceil(math.Log2(float64(self.m)))) + 1
	// x.New(proofSize)

	// fmt.Println("KZG Prover ZERO 1:", self.A[5].IsZero(), self.B[5].IsZero())
	m := self.M
	self.RandomChallenges = make([]mcl.Fr, bits.Len64(m-1))
	i := 0
	for m > 1 {
		ComL, ComR := self.Transform()
		proof.Append(ComL, ComR)
		x := self.FiatShamir()
		self.Fold(x)
		m = m / 2
		self.RandomChallenges[i] = x
		i++
	}
	proof.A[0] = self.A[0]
	proof.B[0] = self.B[0]

	// fmt.Println("KZG Prover ZERO:", self.A[0].IsZero(), self.B[0].IsZero()) // REMOVE
	// Hash(transcript || A || B)
	var a, b mcl.Fr
	data := make([]byte, 0)
	data = append(data, self.Transcript[:]...)
	data = append(data, proof.A[0].Serialize()...)
	data = append(data, proof.B[0].Serialize()...)
	hash := blake2b.Sum256(data)
	copy(self.Transcript[:], hash[:])
	a.SetHashOf(hash[:])
	// fmt.Println("Hash for KZG open", hash) // REMOVE
	fw := BuildHaloPoly(self.RandomChallenges, false)
	proof.W = *self.KZG1.CommitToPoly(fw)
	Pi1, _ := self.KZG1.ComputeProofSingle(fw, &a)
	proof.Pi1 = *Pi1
	if !proof.W.IsEqual(&self.Ck.W[0]) {
		panic("GIPA KZG Prover: W Commitment key computed using GIPA does not match with HaloPoly evaluation.")
	}
	// fmt.Println("Check W", proof.W.IsEqual(&self.Ck.W[0]), proof.Pi1.IsZero(), self.Ck.W[0].IsZero())  // REMOVE

	// Hash(transcript || proof.W)
	data = make([]byte, 0)
	data = append(data, self.Transcript[:]...)
	data = append(data, proof.Pi1.Serialize()...)
	hash = blake2b.Sum256(data)
	copy(self.Transcript[:], hash[:])
	b.SetHashOf(hash[:])
	// fmt.Println("Hash for KZG open2", hash) // REMOVE
	fv := BuildHaloPoly(self.RandomChallenges, true)
	proof.V = *self.KZG2.CommitToPoly(fv)
	Pi2, _ := self.KZG2.ComputeProofSingle(fv, &b)
	proof.Pi2 = *Pi2

	// fmt.Println(self.RandomChallenges) // REMOVE
	if !proof.V.IsEqual(&self.Ck.V[0]) {
		panic("GIPA KZG Prover: V Commitment key computed using GIPA does not match with HaloPoly evaluation.")
	}
	// fmt.Println("Check V", proof.V.IsEqual(&self.Ck.V[0]), proof.Pi2.IsZero(), self.Ck.V[0].IsZero()) // REMOVE
	return proof
}

// func (self *Prover) Print() {
// 	fmt.Println("P:", self.M, self.MPrime,
// 		"len(ck.V):", len(self.Ck.V),
// 		"len(ck.W):", len(self.Ck.W),
// 		"len(X):", len(self.X),
// 		"len(A):", len(self.A),
// 		"len(B):", len(self.B),
// 	)
// }

func (self *Prover) Init(M uint64, ck *cm.Ck, kzg1 *kzg.KZG1Settings, kzg2 *kzg.KZG2Settings, A []mcl.G1, B []mcl.G2) {

	utils.InstanceSizeChecker(M, "GIPA KZG Prover Init: M is not a power of 2")
	utils.SizeMismatchCheck(M, ck.M, "GIPA KZG Prover Init: CK Size:")
	utils.SizeMismatchCheck(2*M-1, uint64(len(kzg1.PK)), "GIPA KZG Prover Init: KZG1 PK Size:")
	utils.SizeMismatchCheck(2*M-1, uint64(len(kzg2.PK)), "GIPA KZG Prover Init: KZG2 PK Size:")
	utils.SizeMismatchCheck(M, uint64(len(A)), "GIPA KZG Prover Init: Vec A Size:")
	utils.SizeMismatchCheck(M, uint64(len(B)), "GIPA KZG Prover Init: Vec B Size:")

	*self = Prover{}
	self.M = M
	self.Ck.Clone(ck)
	self.KZG1 = *kzg1
	self.KZG2 = *kzg2
	self.A = make([]mcl.G1, M)
	self.B = make([]mcl.G2, M)
	copy(self.A, A)
	copy(self.B, B)
}

func (self *Prover) Clone(prover *Prover) {

	self.Init(
		prover.M,
		&prover.Ck,
		&prover.KZG1,
		&prover.KZG2,
		prover.A,
		prover.B,
	)
}

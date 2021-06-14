package gipakzg

import (
	"math/bits"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/utils"
	"github.com/hyperproofs/kzg-go/kzg"
	"golang.org/x/crypto/blake2b"
)

// Verifier is a struct to manage the prover state.
type Verifier struct {
	M   uint64
	Com cm.Com

	MPrime uint64

	ComL cm.Com
	ComR cm.Com

	X []mcl.Fr

	KZG1 kzg.KZG1Settings
	KZG2 kzg.KZG2Settings

	Transcript       [32]byte
	RandomChallenges []mcl.Fr
}

// Transform is a member function of Verifier
// Verifier updates the MPrime
// Parameters
// ----------
// None
//
// Returns
// -------
// None
// Updates the data member, MPrime
func (self *Verifier) Transform() {
	MPrime := self.M / 2
	self.MPrime = MPrime
}

// Fold is a member function of Verifier
// Verifier computes the ck' and com'
// Inner product of A', B' (prover state) should be equal to com'
// Parameters
// ----------
// x, Fr challenge posed to the prover
//
// Returns
// -------
// None
// Updates the data members, com and ck
func (self *Verifier) Fold(x mcl.Fr) {

	var y mcl.Fr
	mcl.FrInv(&y, &x)

	self.M = self.MPrime
	self.X = append(self.X, x)

	self.Com = cm.ComFold(x, y, &self.ComL, &self.Com, &self.ComR)
}

func (self *Verifier) FiatShamir() mcl.Fr {
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

// func (self *Verifier) Verify_(proof Proof, com cm.Com) bool {
// 	self.Com = com
// 	status := self.Verify(proof)
// 	return status
// }

func (self *Verifier) Verify(proof Proof) bool {

	m := self.M
	self.RandomChallenges = make([]mcl.Fr, bits.Len64(m-1))
	i := uint64(0)
	for m > 1 {
		self.Transform()
		ComL, ComR := proof.At(i)
		self.Update(ComL, ComR)
		x := self.FiatShamir()
		self.Fold(x)
		m = m / 2
		self.RandomChallenges[i] = x
		i = i + 1
	}

	var status bool
	status = true
	status = status && self.Check(proof.A[:1], proof.B[:1], proof.W, proof.V)
	// // Hash(transcript || A || B)
	var a, b mcl.Fr
	data := make([]byte, 0)
	data = append(data, self.Transcript[:]...)
	data = append(data, proof.A[0].Serialize()...)
	data = append(data, proof.B[0].Serialize()...)
	hash := blake2b.Sum256(data)
	copy(self.Transcript[:], hash[:])
	a.SetHashOf(hash[:])

	data = make([]byte, 0)
	data = append(data, self.Transcript[:]...)
	data = append(data, proof.Pi1.Serialize()...)
	hash = blake2b.Sum256(data)
	copy(self.Transcript[:], hash[:])
	b.SetHashOf(hash[:])

	yw := EvaluateHaloPoly(self.RandomChallenges, a, false)
	yv := EvaluateHaloPoly(self.RandomChallenges, b, true)

	status = status && self.KZG1.CheckProofSingle(&proof.W, &proof.Pi1, &a, &yw)
	status = status && self.KZG2.CheckProofSingle(&proof.V, &proof.Pi2, &b, &yv)
	return status
}

func (self *Verifier) Update(ComL cm.Com, ComR cm.Com) {
	self.ComR = ComR
	self.ComL = ComL
}

// Challenge is a member function of Verifier. Will be defunct after adding Fiat-Shamir
// It poses a random challenge to the prover based on ComL and ComR
// Parameters
// ----------
// ComL, type Com
// ComR, type Com
//
// Returns
// -------
// x, Fr a random challenge
// Updates the data members, ComR and ComL
func (self *Verifier) Challenge() mcl.Fr {

	var x mcl.Fr
	x.Random()
	// x.SetInt64(1)
	return x
}

// Check is a member function of Verifier
// It performs the final pairing and commitment check.
// Parameters
// ----------
// A, slice mcl.G1 should be of size 1
// B, slice mcl.G2 should be of size 1
//
// Returns
// -------
// bool, true if the verification is successful.
func (self *Verifier) Check(A []mcl.G1, B []mcl.G2, W mcl.G1, V mcl.G2) bool {
	var result mcl.GT
	mcl.Pairing(&result, &A[0], &B[0])
	ck := cm.Ck{1, []mcl.G2{V}, []mcl.G1{W}} // Prover gives W and V
	comProver := cm.Com{}
	comProver = cm.IPPCM(&ck, A, B, result)
	return self.Com.IsEqual(&comProver)
}

// func (self *Verifier) Print() {
// 	fmt.Println("V:", self.M, self.MPrime,
// 		"len(X):", len(self.X),
// 		// "len(A):", len(self.A),
// 	)
// }

func (self *Verifier) Init(M uint64, kzg1 *kzg.KZG1Settings, kzg2 *kzg.KZG2Settings, com cm.Com) {

	utils.InstanceSizeChecker(M, "GIPA KZG Verifier Init: M is not a power of 2")
	utils.SizeMismatchCheck(2*M-1, uint64(len(kzg1.PK)), "GIPA KZG Verifier Init: KZG1 PK Size:")
	utils.SizeMismatchCheck(2*M-1, uint64(len(kzg2.PK)), "GIPA KZG Verifier Init: KZG2 PK Size:")

	*self = Verifier{}
	self.M = M
	self.KZG1 = *kzg1
	self.KZG2 = *kzg2
	self.Com = com
}

func (self *Verifier) Clone(verifier *Verifier) {
	self.Init(
		verifier.M,
		&verifier.KZG1,
		&verifier.KZG2,
		verifier.Com,
	)
}

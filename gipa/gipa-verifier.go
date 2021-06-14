package gipa

import (
	"fmt"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/utils"
	"golang.org/x/crypto/blake2b"
)

// Verifier is a struct to manage the prover state.
type Verifier struct {
	M   uint64
	Ck  cm.Ck
	Com cm.Com

	MPrime uint64

	ComL cm.Com
	ComR cm.Com

	X []mcl.Fr

	Transcript [32]byte
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

	cm.CkFold(&self.Ck, x, y, &self.Ck)
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
	i := uint64(0)
	for m > 1 {
		self.Transform()
		ComL, ComR := proof.At(i)
		self.Update(ComL, ComR)
		x := self.FiatShamir()
		self.Fold(x)
		m = m / 2
		i = i + 1
	}
	return self.Check(proof.A[:1], proof.B[:1])
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
func (self *Verifier) Check(A []mcl.G1, B []mcl.G2) bool {
	var result mcl.GT
	mcl.Pairing(&result, &A[0], &B[0])
	comProver := cm.Com{}
	comProver = cm.IPPCM(&self.Ck, A, B, result)
	return self.Com.IsEqual(&comProver)
}

func (self *Verifier) Print() {
	fmt.Println("V:", self.M, self.MPrime,
		"len(ck.V):", len(self.Ck.V),
		"len(ck.W):", len(self.Ck.W),
		"len(X):", len(self.X),
		// "len(A):", len(self.A),
	)
}

func (self *Verifier) Init(M uint64, ck *cm.Ck, com cm.Com) {

	utils.InstanceSizeChecker(M, "GIPA Verifier Init: M is not a power of 2")
	utils.SizeMismatchCheck(M, ck.M, "GIPA Verifier Init: CK Size:")

	*self = Verifier{}
	self.M = M
	self.Ck.Clone(ck)
	self.Com = com
}

func (self *Verifier) Clone(verifier *Verifier) {
	self.Init(
		verifier.M,
		&verifier.Ck,
		verifier.Com)
}

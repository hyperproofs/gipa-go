package batchplain

import (
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/gipa"
	"github.com/hyperproofs/gipa-go/utils"
	"golang.org/x/crypto/blake2b"
)

type Verifier struct {
	Verifier gipa.Verifier
	W        []mcl.G1
	N        uint32 // Be sure to do ceil when padding
	M        uint32
	MN       uint64 // In hyperproofs we may have to pad vector A and B. Thus self.N * self.M may not be equal to self.MN
	B        []mcl.G2
	P        []mcl.G1
	Q        []mcl.G2
}

func (self *Verifier) FiatShamir(Transcript []byte, T mcl.GT) mcl.Fr {
	var x mcl.Fr
	// x = VerifierChallenges
	data := make([]byte, 0)
	data = append(data, Transcript...)
	data = append(data, T.Serialize()...)
	hash := blake2b.Sum256(data)
	copy(self.Verifier.Transcript[:], hash[:])
	x.SetHashOf(hash[:])
	return x
}

// // Just verify the AGGGIPA proofs
// func (self *Verifier) Verify_(proof Proof, P []mcl.G1, Q []mcl.G2, B []mcl.G2) bool {
// 	// self.P = make([]mcl.G1, len(P))
// 	// self.Q = make([]mcl.G2, len(Q))
// 	// self.B = make([]mcl.G2, len(B))
// 	// copy(self.P, P)
// 	// copy(self.Q, Q)
// 	// copy(self.B, B)
// 	self.P = make([]mcl.G1, self.N)
// 	self.Q = make([]mcl.G2, self.N)
// 	self.B = make([]mcl.G2, self.MN)
// 	copy(self.P, P)
// 	copy(self.Q, Q)
// 	copy(self.B, B)
// 	status := self.Verify(proof)
// 	return status
// }

func (self *Verifier) Verify(proof Proof) bool {

	m := int(self.M)
	r := self.FiatShamir(self.Verifier.Transcript[:], proof.T) // Transcript is initially empty
	self.B = utils.G2VecRandExpo(self.B, r, m)                 // For P vector, M == 1 there is only one pairing on the lhs
	self.P = utils.G1VecRandExpo(self.P, r, 1)                 // For P vector, M == 1 there is only one pairing on the lhs
	U := utils.InnerProd(self.W, self.B)
	Z := utils.InnerProd(self.P, self.Q) // In Edrax we can get away with just one pairing
	com := cm.Com{}
	com.Com[0] = proof.T
	com.Com[1] = U
	com.Com[2] = Z
	self.Verifier.Com = com
	status := self.Verifier.Verify(proof.GipaProof)
	return status
}

// func (self *Verifier) VerifyEdrax_(proof Proof, P []mcl.G1, Q []mcl.G2, B []mcl.G2) bool {
// 	// self.P = make([]mcl.G1, len(P))
// 	// self.Q = make([]mcl.G2, len(Q))
// 	// self.B = make([]mcl.G2, len(B))
// 	// copy(self.P, P)
// 	// copy(self.Q, Q)
// 	// copy(self.B, B)
// 	self.P = make([]mcl.G1, self.N)
// 	self.Q = make([]mcl.G2, self.N)
// 	self.B = make([]mcl.G2, self.MN)
// 	copy(self.P, P)
// 	copy(self.Q, Q)
// 	copy(self.B, B)
// 	status := self.VerifyEdrax(proof)
// 	return status
// }

// GIPA + Edrax. Check the overleaf BMMV19 notes.
func (self *Verifier) VerifyEdrax(proof Proof) bool {

	m := int(self.M)
	r := self.FiatShamir(self.Verifier.Transcript[:], proof.T)
	self.B = utils.G2VecRandExpo(self.B, r, m) // For P vector, M == 1 there is only one pairing on the lhs
	self.P = utils.G1VecRandExpo(self.P, r, 1) // For P vector, M == 1 there is only one pairing on the lhs
	U := utils.InnerProd(self.W, self.B)
	var Psum mcl.G1
	for i := range self.P {
		mcl.G1Add(&Psum, &Psum, &self.P[i])
	}

	pTemp := []mcl.G1{Psum}
	qTemp := []mcl.G2{self.Q[0]}

	Z := utils.InnerProd(pTemp, qTemp) // In Edrax we can get away with just one pairing

	com := cm.Com{}
	com.Com[0] = proof.T
	com.Com[1] = U
	com.Com[2] = Z
	self.Verifier.Com = com
	status := self.Verifier.Verify(proof.GipaProof)
	return status
}

func (self *Verifier) Init(M uint32, N uint32, MN uint64, ck *cm.Ck, P []mcl.G1, Q []mcl.G2, B []mcl.G2) {

	utils.InstanceSizeChecker(MN, "BatchPlain Verifier Init: M is not a power of 2")
	utils.SizeMismatchCheck(MN, ck.M, "BatchPlain Verifier Init: W Size:")
	utils.SizeMismatchCheck(uint64(N), uint64(len(P)), "BatchPlain Verifier Init: P Size:")
	utils.SizeMismatchCheck(uint64(N), uint64(len(Q)), "BatchPlain Verifier Init: Q Size:")
	utils.SizeMismatchCheck(MN, uint64(len(B)), "BatchPlain Verifier Init: B Size:")

	*self = Verifier{}
	self.N = N
	self.M = M
	self.MN = MN
	com := cm.Com{} //No need to set proper com, as it will rewritten in Verify() or EdraxVerify()

	self.Verifier.Init(MN, ck, com)
	self.W = make([]mcl.G1, MN)
	copy(self.W, ck.W)

	self.P = make([]mcl.G1, N)
	self.Q = make([]mcl.G2, N)
	self.B = make([]mcl.G2, MN)

	copy(self.P, P)
	copy(self.Q, Q)
	copy(self.B, B)
}

// Use this only if you need to deepcopy
func (self *Verifier) Clone(verifier *Verifier) {
	self.Init(
		verifier.M,
		verifier.N,
		verifier.MN,
		&verifier.Verifier.Ck,
		verifier.P,
		verifier.Q,
		verifier.B)
}

package batch

import (
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/cm"
	"github.com/hyperproofs/gipa-go/gipakzg"
	"github.com/hyperproofs/gipa-go/utils"
	"github.com/hyperproofs/kzg-go/kzg"
	"golang.org/x/crypto/blake2b"
)

type Prover struct {
	Prover gipakzg.Prover
	N      uint32 // Product of two 32 bits will be at most 64 bits
	M      uint32 // Product of two 32 bits will be at most 64 bits
	MN     uint64 // In hyperproofs we may have to pad vector A and B. Thus self.N * self.M may not be equal to self.MN
	// Prover does not use N. But verifier uses: N, M, and MN.
}

// func (self *Prover) Prove_(A []mcl.G1, B []mcl.G2) Proof {
// 	self.Prover.A = make([]mcl.G1, self.MN)
// 	self.Prover.B = make([]mcl.G2, self.MN)
// 	copy(self.Prover.A, A)
// 	copy(self.Prover.B, B)

// 	proof := self.Prove()
// 	return proof
// }

func (self *Prover) Prove() Proof {

	proof := Proof{}

	T := utils.InnerProd(self.Prover.A, self.Prover.Ck.V)
	proof.T = T

	r := self.FiatShamir(self.Prover.Transcript[:], proof.T)
	m := int(self.M)
	self.Prover.B = utils.G2VecRandExpo(self.Prover.B, r, m)
	proof.GipaKzgProof = self.Prover.Prove()
	return proof
}

func (self *Prover) FiatShamir(Transcript []byte, T mcl.GT) mcl.Fr {
	var x mcl.Fr
	// x = VerifierChallenges
	data := make([]byte, 0)
	data = append(data, Transcript...)
	data = append(data, T.Serialize()...)
	hash := blake2b.Sum256(data)
	copy(self.Prover.Transcript[:], hash[:])
	x.SetHashOf(hash[:])
	return x
}

func (self *Prover) Init(M uint32, N uint32, MN uint64, ck *cm.Ck, kzg1 *kzg.KZG1Settings, kzg2 *kzg.KZG2Settings, A []mcl.G1, B []mcl.G2) {

	utils.InstanceSizeChecker(MN, "Batch Prover Init: M is not a power of 2")
	utils.SizeMismatchCheck(MN, ck.M, "Batch Prover Init: Ck Size:")
	utils.SizeMismatchCheck(2*MN-1, uint64(len(kzg1.PK)), "Batch Prover Init: KZG1 PK Size:")
	utils.SizeMismatchCheck(2*MN-1, uint64(len(kzg2.PK)), "Batch Prover Init: KZG2 PK Size:")
	utils.SizeMismatchCheck(MN, uint64(len(A)), "Batch Prover Init: A Size:")
	utils.SizeMismatchCheck(MN, uint64(len(B)), "Batch Prover Init: B Size:")

	*self = Prover{}
	self.N = N
	self.M = M
	self.MN = MN
	self.Prover.Init(MN, ck, kzg1, kzg2, A, B)
}

// Use this only if you need to deepcopy
func (self *Prover) Clone(prover *Prover) {
	self.Init(
		prover.M,
		prover.N,
		prover.MN,
		&prover.Prover.Ck,
		&prover.Prover.KZG1,
		&prover.Prover.KZG2,
		prover.Prover.A,
		prover.Prover.B,
	)
}

package cm

import (
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/utils"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// Transform is a member of Ck.
// Given a ck of size m, it returns two m/2 sized ck which are cross-connected (illustrated below).
// Example:
// Given ck.V, ck.W
// Ck1 = (ck.V[:m/2], ck.W[m/2:])
// Ck2 = (ck.V[m/2:], ck.W[:m/2])
// TODO: Take in Ck1 and Ck1 as references in the function call to reduce overheads
// Parameters
// ----------
// None
//
// Returns
// -------
// - Ck1 m/2 sized commitment key
// - Ck2 m/2 sized commitment key
func (ck *Ck) Transform(Ck1 *Ck, Ck2 *Ck) {

	MPrime := ck.M / 2
	*Ck1 = Ck{MPrime, make([]mcl.G2, MPrime), make([]mcl.G1, MPrime)}
	*Ck2 = Ck{MPrime, make([]mcl.G2, MPrime), make([]mcl.G1, MPrime)}

	copy(Ck1.V, ck.V[:MPrime])
	copy(Ck1.W, ck.W[MPrime:])

	copy(Ck2.V, ck.V[MPrime:])
	copy(Ck2.W, ck.W[:MPrime])
}

// IsEqual is a member function of Com
// Checks if two commitments are the same
//
// Parameters
// ----------
// com: Com
//
// Returns
// -------
// bool, true if all the members self.com equals com
func (self *Com) IsEqual(com *Com) bool {

	var result bool
	result = true
	for i := range self.Com {
		result = result && self.Com[i].IsEqual(&com.Com[i])
		// fmt.Println("Checking the equality of the commitment", i, result)
		if !result {
			break
		}
	}
	return result
}

// New is a constructor for the Ck struct. Assigns default values to the data members
// Parameters
// ----------
// m: Size of the commitment keys
// 	Size of the commitment key should be same as the size of the message
// 	This code works only when the size if a power of 2
//
// Returns
// -------
// None
func (ck *Ck) New(m uint64) {

	if m < 1 || !utils.IsPow2(m) {
		// Error handling
		// Check if m is a power of 2
		panic("Ck: New: Error")
	}

	ck.M = m
	ck.W = make([]mcl.G1, m)
	ck.V = make([]mcl.G2, m)
}

func (self *Ck) Clone(ck *Ck) {

	utils.InstanceSizeChecker(ck.M, "Ck: Clone: Error")
	self.M = ck.M
	self.V = make([]mcl.G2, len(ck.V))
	self.W = make([]mcl.G1, len(ck.W))
	copy(self.V, ck.V)
	copy(self.W, ck.W)
}

package batchplain

import (
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/gipa"
)

type Proof struct {
	T         mcl.GT
	GipaProof gipa.Proof
}

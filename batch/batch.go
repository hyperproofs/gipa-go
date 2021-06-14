package batch

import (
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/gipakzg"
)

type Proof struct {
	T            mcl.GT
	GipaKzgProof gipakzg.Proof
}

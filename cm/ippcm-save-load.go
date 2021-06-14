package cm

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/gipa-go/utils"
	"github.com/hyperproofs/kzg-go/kzg"
)

// Saves the commitment keys to a folder.
// Input: ck, folderPath
// Files are saved in folderPath/CK.data
func IPPSave(ck *Ck, folderPath string) {

	os.MkdirAll(folderPath, os.ModePerm)
	fileName := folderPath + "/CK.data"
	f, err := os.Create(fileName)
	check(err)
	fmt.Println(fileName)

	intBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(intBytes, ck.M)
	_, err = f.Write(intBytes)
	check(err)

	for i := uint64(0); i < ck.M; i++ {
		_, err = f.Write(ck.W[i].Serialize())
		check(err)
		_, err = f.Write(ck.V[i].Serialize())
		check(err)
	}

	fmt.Println("Dumped ", fileName)
	defer f.Close()
}

// Loads the commitment keys from a folder.
// Input: M, folderPath
// Files are saved in folderPath/CK.data
// M needs to be a power of 2
func IPPCMLoad(M uint64, folderPath string) Ck {

	fileName := folderPath + "/CK.data"
	f, err := os.Open(fileName)
	check(err)

	var m uint64
	data := make([]byte, 8)

	_, err = f.Read(data)

	m = binary.LittleEndian.Uint64(data)

	if M > m {
		panic("CK Load Error: There is not enough to read")
	}
	ck := Ck{M, make([]mcl.G2, M), make([]mcl.G1, M)}

	dataG1 := make([]byte, utils.GetG1ByteSize())
	dataG2 := make([]byte, utils.GetG2ByteSize())
	for i := uint64(0); i < ck.M; i++ {
		_, err = f.Read(dataG1)
		check(err)
		ck.W[i].Deserialize(dataG1)
		_, err = f.Read(dataG2)
		check(err)
		ck.V[i].Deserialize(dataG2)
	}

	defer f.Close()
	return ck
}

// Saves the commitment keys to a folder.
// Input: ck, kzg1, kzg2, folderPath
// Files are saved in folderPath/CK.data
func IPPSaveCmKzg(ck *Ck, kzg1 *kzg.KZG1Settings, kzg2 *kzg.KZG2Settings, folderPath string) {

	IPPSave(ck, folderPath)

	os.MkdirAll(folderPath, os.ModePerm)
	fileName := folderPath + "/KZG.data"
	f, err := os.Create(fileName)
	check(err)
	fmt.Println(fileName)

	degree := uint64(len(kzg1.PK))
	if degree != 2*ck.M-1 {
		panic("CK and KZG size mismatch")
	}

	intBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(intBytes, degree)
	_, err = f.Write(intBytes)
	check(err)

	// Write VK
	{
		for i := 0; i < len(kzg1.VK); i++ {
			_, err = f.Write(kzg1.VK[i].Serialize())
			check(err)
			_, err = f.Write(kzg2.VK[i].Serialize())
			check(err)
		}
	}

	// Write PK
	{
		for i := uint64(0); i < degree; i++ {
			_, err = f.Write(kzg1.PK[i].Serialize())
			check(err)
			_, err = f.Write(kzg2.PK[i].Serialize())
			check(err)
		}
	}

	// fileName := folderPath + "/CK.data"
	// f, err := os.Create(fileName)

	fmt.Println("Dumped ", fileName)
	defer f.Close()
}

// Loads the commitment keys and KZG keys from a folder.
// Input: M, folderPath
// Files are saved in folderPath/CK.data
// M needs to be a power of 2
func IPPCMLoadCmKzg(M uint64, folderPath string) (Ck, kzg.KZG1Settings, kzg.KZG2Settings) {

	ck := IPPCMLoad(M, folderPath)

	fileName := folderPath + "/KZG.data"
	f, err := os.Open(fileName)
	check(err)

	var m uint64
	data := make([]byte, 8)

	_, err = f.Read(data)

	m = binary.LittleEndian.Uint64(data)
	kzgM := 2*M - 1
	if m < kzgM {
		panic("CK KZG Load Error: There is not enough to read")
	}

	dataG1 := make([]byte, utils.GetG1ByteSize())
	dataG2 := make([]byte, utils.GetG2ByteSize())

	kzg1 := kzg.KZG1Settings{PK: make([]mcl.G1, kzgM), VK: make([]mcl.G2, 2)}
	kzg2 := kzg.KZG2Settings{PK: make([]mcl.G2, kzgM), VK: make([]mcl.G1, 2)}

	// Read VK
	{
		for i := 0; i < 2; i++ {
			_, err = f.Read(dataG2)
			check(err)
			kzg1.VK[i].Deserialize(dataG2)

			_, err = f.Read(dataG1)
			check(err)
			kzg2.VK[i].Deserialize(dataG1)
		}
	}
	// Read PK
	{
		for i := uint64(0); i < kzgM; i++ {
			_, err = f.Read(dataG1)
			check(err)
			kzg1.PK[i].Deserialize(dataG1)

			_, err = f.Read(dataG2)
			check(err)
			kzg2.PK[i].Deserialize(dataG2)
		}
	}
	defer f.Close()
	return ck, kzg1, kzg2
}

func LoadKeys(M uint64, folderPath string) (Ck, kzg.KZG1Settings, kzg.KZG2Settings) {

	ck, kzg1, kzg2 := IPPCMLoadCmKzg(M, folderPath)
	return ck, kzg1, kzg2
}

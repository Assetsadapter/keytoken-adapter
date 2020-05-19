package keytoken_txsigner

import (
	"bytes"
	"encoding/gob"
	"github.com/Assetsadapter/keytoken-adapter/utils"
)

const Lenthaddr = 47

type Address [Lenthaddr]byte

func BytesToAddress(from []byte) Address {

	var addr Address

	copy(addr[:], from[:])
	return addr
}

func (a *Address) AddressToByte() []byte {
	var b []byte
	b = a[:]
	return b
}

func (a *Address) AddrToPub() []byte {
	addr := a.AddressToByte()

	addr = addr[3:]
	pub := utils.Decode(string(addr))
	return pub

}

func AddrTopub(addr string) []byte {
	var b []byte
	b = []byte(addr[3:])
	pub := utils.Decode(string(b))
	return pub

}
func Encode(v interface{}) ([]byte, error) {
	var buf bytes.Buffer

	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Decode(data []byte, v interface{}) error {
	return gob.NewDecoder(bytes.NewReader(data)).Decode(v)
}

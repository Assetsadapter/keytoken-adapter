package keytoken

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Assetsadapter/keytoken-adapter/utils"
	"github.com/blocktree/go-owcdrivers/addressEncoder"
)

const (
	KTOPrefix   = "Kto"
	KTOLen  = 47
)

var (
	KTO_mainnetAddressP2PKH = addressEncoder.AddressType{"base58", addressEncoder.BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x3f}, nil}
)

//AddressDecoder 地址解析器
type AddressDecoder struct{}

//PrivateKeyToWIF 私钥转WIF
func (decoder *AddressDecoder) PrivateKeyToWIF(priv []byte, isTestnet bool) (string, error) {
	return "", nil

}

//PublicKeyToAddress 公钥转地址
func (decoder *AddressDecoder) PublicKeyToAddress(pub []byte, isTestnet bool) (string, error) {
	
	encodePub := utils.Encode(pub)
	pubStr := hex.EncodeToString(pub)
	addr := KTOPrefix + encodePub
	if len(addr) != KTOLen {
		return "", errors.New(fmt.Sprintf("PublicKeyToAddress failed, error = address length is invalid, length is %d, pub key is %s", len(addr), pubStr))
	}
	return addr, nil
}

//RedeemScriptToAddress 多重签名赎回脚本转地址
func (decoder *AddressDecoder) RedeemScriptToAddress(pubs [][]byte, required uint64, isTestnet bool) (string, error) {
	return "", nil
}

//WIFToPrivateKey WIF转私钥
func (decoder *AddressDecoder) WIFToPrivateKey(wif string, isTestnet bool) ([]byte, error) {
	return nil, nil

}

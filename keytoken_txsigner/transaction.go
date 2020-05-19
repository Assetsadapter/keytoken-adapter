package keytoken_txsigner

import (
    "bytes"
    "github.com/Assetsadapter/keytoken-adapter/utils"
    "github.com/Assetsadapter/keytoken-adapter/utils/miscellaneous"
    "time"
    
    "golang.org/x/crypto/ed25519"
    "golang.org/x/crypto/sha3"
)

const (
    KTOPrefix = "Kto"
)

type Transaction struct {
    Nonce     uint64  `json:"nonce"`
    Amount    uint64  `json:"amount"`
    From      Address `json:"from"`
    To        Address `json:"to"`
    Hash      []byte  `json:"hash"`
    Signature []byte  `json:"signature"`
    Time      int64   `json:"time"`
}

func NewTransaction(nonce, amount uint64, from, to string) *Transaction {
    tx := &Transaction{
        Nonce:  nonce,
        Amount: amount,
        From:   BytesToAddress([]byte(from)),
        To:     BytesToAddress([]byte(to)),
        Time:   time.Now().Unix(),
    }
    
    tx.HashTransaction()
    return tx
}

func (tx *Transaction) HashTransaction() {
    fromBytes := tx.From[:]
    toBytes := tx.To[:]
    nonceBytes := miscellaneous.E64func(tx.Nonce)
    amountBytes := miscellaneous.E64func(tx.Amount)
    timeBytes := miscellaneous.E64func(uint64(tx.Time))
    txBytes := bytes.Join([][]byte{nonceBytes, amountBytes, fromBytes, toBytes, timeBytes}, []byte{})
    hash := sha3.Sum256(txBytes)
    tx.Hash = hash[:]
}

func (tx *Transaction) Sgin(privateKey []byte) {
    signature := ed25519.Sign(ed25519.PrivateKey(privateKey), tx.Hash)
    tx.Signature = signature
}

func (tx *Transaction) TrimmedCopy() *Transaction {
    txCopy := &Transaction{
        Nonce:  tx.Nonce,
        Amount: tx.Amount,
        From:   tx.From,
        To:     tx.To,
        Time:   tx.Time,
    }
    return txCopy
}

func (tx *Transaction) Verify() bool {
    txCopy := tx.TrimmedCopy()
    txCopy.HashTransaction()
    publicKey := AddressToPublicKey(string(tx.From[:]))
    return ed25519.Verify(publicKey, txCopy.Hash, tx.Signature)
}

func AddressToPublicKey(address string) []byte {
    return utils.Decode(address[len(KTOPrefix):])
}

/*
 * Copyright 2018 The openwallet Authors
 * This file is part of the openwallet library.
 *
 * The openwallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The openwallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */
package keytoken

import (
	"context"
	"errors"
	"fmt"
	
	//"log"
	"math/big"
	"sort"
	"strconv"
	"strings"
	
	"time"
	
	"github.com/Assetsadapter/keytoken-adapter/message"
	"github.com/blocktree/openwallet/log"
	"github.com/blocktree/openwallet/openwallet"
)

type Client struct {
	Debug         bool
	GreeterClient message.GreeterClient
}

type Response struct {
	Id      int         `json:"id"`
	Version string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
}

/*
1. eth block example
   "result": {
        "difficulty": "0x1a4f1f",
        "extraData": "0xd98301080d846765746888676f312e31302e338664617277696e",
        "gasLimit": "0x47e7c4",
        "gasUsed": "0x5b61",
        "hash": "0x85319757555e1cf069684dde286e3c34331dc27d2e54bed24e7291f1b84a0cc5",
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "miner": "0x50068fd632c1a6e6c5bd407b4ccf8861a589e776",
        "mixHash": "0xb0cb0abb00c3fc77014abb2a520e3d2a14047cfa30a3b954f18fbeefd1a92f7b",
        "nonce": "0x4df323f58b7a7fd0",
        "number": "0x169cf",
        "parentHash": "0x3df7035473ec98c8c18d2785d5a345193a32b95fcf1ac2d3f09a93109feed3bc",
        "receiptsRoot": "0x441a5be885777bfdf0e985a8ef5046316b3384dd49db7ef95b2c546611c1e2fc",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "size": "0x2aa",
        "stateRoot": "0xb0d76a848be723c72c9639b2de591320f4456b665354995be08a8fa83897efbb",
        "timestamp": "0x5b7babbe",
        "totalDifficulty": "0x2a844e200a",
        "transactions": [
            {
                "blockHash": "0x85319757555e1cf069684dde286e3c34331dc27d2e54bed24e7291f1b84a0cc5",
                "blockNumber": "0x169cf",
                "from": "0x50068fd632c1a6e6c5bd407b4ccf8861a589e776",
                "gas": "0x15f90",
                "gasPrice": "0x430e23400",
                "hash": "0x925e33ac3ebaf40bb44a843860b6589ea2df78c955a27f9df16edcf789519671",
                "input": "0x70a082310000000000000000000000002a63b2203955b84fefe52baca3881b3614991b34",
                "nonce": "0x45",
                "to": "0x8847e5f841458ace82dbb0692c97115799fe28d3",
                "transactionIndex": "0x0",
                "value": "0x0",
                "v": "0x3c",
                "r": "0x8d2ffbe7cb7ac1159a999dfa4352fa27f5cce0df8755254393838aab229ecd33",
                "s": "0xe8ed1f7f8de902ccb008824fe39b2903b94f89e3ea0d5b9f9b880c302bae6cf"
            }
        ],
        "transactionsRoot": "0xa8cb62696679bc3d72762bd2aa5842fdd8aed9c9691fe82064c13e854c13d5cb",
        "uncles": []
    }
*/

type EthBlock struct {
	BlockHeader
	Transactions []BlockTransaction `json:"transactions"`
}

func (this *EthBlock) CreateOpenWalletBlockHeader() *openwallet.BlockHeader {
	header := &openwallet.BlockHeader{
		Hash:              this.BlockHash,
		Previousblockhash: this.PreviousHash,
		Height:            this.BlockHeight,
		Time:              uint64(time.Now().Unix()),
	}
	return header
}

func (this *EthBlock) Init() error {
	var err error
	this.BlockHeight, err = strconv.ParseUint(removeOxFromHex(this.BlockNumber), 16, 64) //ConvertToBigInt(this.BlockNumber, 16) //
	if err != nil {
		log.Errorf("init blockheight failed, err=%v", err)
		return err
	}
	return nil
}

type TxpoolContent struct {
	Pending map[string]map[string]BlockTransaction `json:"pending"`
}

func (this *TxpoolContent) GetSequentTxNonce(addr string) (uint64, uint64, uint64, error) {
	txpool := this.Pending
	var target map[string]BlockTransaction
	for theAddr, _ := range txpool {
		if strings.ToLower(theAddr) == strings.ToLower(addr) {
			target = txpool[theAddr]
		}
	}
	
	nonceList := make([]interface{}, 0)
	for n, _ := range target {
		tn, err := strconv.ParseUint(n, 10, 64)
		if err != nil {
			log.Error("parse nonce[", n, "] in txpool to uint faile, err=", err)
			return 0, 0, 0, err
		}
		nonceList = append(nonceList, tn)
	}
	
	sort.Slice(nonceList, func(i, j int) bool {
		if nonceList[i].(uint64) < nonceList[j].(uint64) {
			return true
		}
		return false
	})
	
	var min, max, count uint64
	for i := 0; i < len(nonceList); i++ {
		if i == 0 {
			min = nonceList[i].(uint64)
			max = min
			count++
		} else if nonceList[i].(uint64) != max+1 {
			break
		} else {
			max++
			count++
		}
	}
	return min, max, count, nil
}

func (this *TxpoolContent) GetPendingTxCountForAddr(addr string) int {
	txpool := this.Pending
	if _, exist := txpool[addr]; !exist {
		return 0
	}
	if txpool[addr] == nil {
		return 0
	}
	return len(txpool[addr])
}

// 获取地址交易nonce值
func (this *Client) ktoGetAddressNonceAt(addr string) (uint64, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	respNonce, err := this.GreeterClient.GetAddressNonceAt(ctx, &message.ReqNonce{Address:addr})
	if err != nil {
		log.Errorf("GetAddressNonceAt failed, error = %s", err.Error())
		return 0, err
	}
	return respNonce.Nonce, nil
}

// 以txid获取交易详情
func (this *Client) GetTxByHash(txid string) (*BlockTransaction, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	respTx, err := this.GreeterClient.GetTxByHash(ctx, &message.ReqTxByHash{Hash: txid})
	if err != nil {
		log.Errorf("GetTxByHash failed, error = %s\n", err.Error())
		return nil, err
	}
	return ParseToBlockTransaction(respTx), nil
}

// 以区块号获取区块详情
func (this *Client) KtoGetBlockByNum(blockNum uint64) (*EthBlock, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	respBlock, err := this.GreeterClient.GetBlockByNum(ctx, &message.ReqBlockByNumber{Height: blockNum})
	if err != nil {
		log.Errorf("GetBlockByNum failed, error = %s\n", err.Error())
		return nil, err
	}
	block := &EthBlock{
		BlockHeader:  *NewBlockHeader(respBlock),
		Transactions: ParseToBlockTransactions(respBlock),
	}
	return block, nil
}

//func (this *Client) ethGetTxpoolStatus() (uint64, uint64, error) {
//	result, err := this.Call("txpool_status", 1, nil)
//	if err != nil {
//		//errInfo := fmt.Sprintf("get block[%v] failed, err = %v \n", blockNumStr,  err)
//		//log.Errorf("get block[%v] failed, err = %v \n", err)
//		return 0, 0, err
//	}
//
//	type TxPoolStatus struct {
//		Pending string `json:"pending"`
//		Queued  string `json:"queued"`
//	}
//
//	txStatusResult := TxPoolStatus{}
//	err = json.Unmarshal([]byte(result.Raw), &txStatusResult)
//	if err != nil {
//		log.Errorf("decode from json failed, err=%v", err)
//		return 0, 0, err
//	}
//
//	pendingNum, err := strconv.ParseUint(removeOxFromHex(txStatusResult.Pending), 16, 64)
//	if err != nil {
//		log.Errorf("convert txstatus pending number to uint failed, err=%v", err)
//		return 0, 0, err
//	}
//
//	queuedNum, err := strconv.ParseUint(removeOxFromHex(txStatusResult.Queued), 16, 64)
//	if err != nil {
//		log.Errorf("convert queued number to uint failed, err=%v", err)
//		return 0, 0, err
//	}
//
//	return pendingNum, queuedNum, nil
//}

// 获取地址余额
func (this *Client) GetAddrBalance(address string) (*big.Int, error) {
	//if sign != "latest" && sign != "pending" {
	//	return nil, errors.New("unknown sign was put through.")
	//}
	//
	//params := []interface{}{
	//	AppendOxToAddress(address),
	//	sign,
	//}
	//result, err := this.Call("eth_getBalance", 1, params)
	//if err != nil {
	//	//log.Errorf(fmt.Sprintf("get addr[%v] balance failed, err=%v\n", address, err))
	//	return big.NewInt(0), err
	//}
	//if result.Type != gjson.String {
	//	errInfo := fmt.Sprintf("get addr[%v] balance result type error, result type is %v\n", address, result.Type)
	//	log.Errorf(errInfo)
	//	return big.NewInt(0), errors.New(errInfo)
	//}
	//
	//balance, err := ConvertToBigInt(result.String(), 16)
	//if err != nil {
	//	errInfo := fmt.Sprintf("convert addr[%v] balance format to bigint failed, response is %v, and err = %v\n", address, result.String(), err)
	//	log.Errorf(errInfo)
	//	return big.NewInt(0), errors.New(errInfo)
	//}
	//return balance, nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := this.GreeterClient.GetBalance(ctx, &message.ReqBalance{Address: address})
	if err != nil {
		log.Errorf("get balance failed, error = %s \n", err.Error())
		return big.NewInt(0), err
	}
	balance, _ := big.NewInt(0).SetString(fmt.Sprintf("%d", resp.Balnce), 10)
	return balance, nil
}

// 发送需要线上签名的交易
func (this *WalletManager) SendTransactionToAddr(param map[string]interface{}) (string, error) {
	//(addr *Address, to string, amount *big.Int, password string, fee *txFeeInfo) (string, error) {
	var exist bool
	var temp interface{}
	if temp, exist = param["from"]; !exist {
		log.Errorf("from not found.")
		return "", errors.New("from not found.")
	}
	
	fromAddr := temp.(string)
	
	if temp, exist = param["password"]; !exist {
		log.Errorf("password not found.")
		return "", errors.New("password not found.")
	}
	
	password := temp.(string)
	
	err := this.WalletClient.UnlockAddr(fromAddr, password, 300)
	if err != nil {
		log.Errorf("unlock addr failed, err = %v", err)
		return "", err
	}
	
	txId, err := this.WalletClient.ktoSendTransaction(param)
	if err != nil {
		log.Errorf("ktoSendTransaction failed, err = %v", err)
		return "", err
	}
	
	err = this.WalletClient.LockAddr(fromAddr)
	if err != nil {
		log.Errorf("lock addr failed, err = %v", err)
		return txId, err
	}
	
	return txId, nil
}

// 发送离线签名的交易
func (this *WalletManager) KtoSendRawTransaction(from, to string, amount, nonce uint64, time int64, hash, signature []byte) (string, error) {
	return this.WalletClient.ktoSendRawTransaction(from, to, amount, nonce, time, hash, signature)
}

// 发送离线签名的交易
func (this *Client) ktoSendRawTransaction(from, to string, amount, nonce uint64, time int64, hash, signature []byte) (string, error) {
	//params := []interface{}{
	//	signedTx,
	//}
	//
	//result, err := this.Call("eth_sendRawTransaction", 1, params)
	//if err != nil {
	//	log.Errorf(fmt.Sprintf("start raw transaction faield, err = %v \n", err))
	//	return "", err
	//}
	//
	//if result.Type != gjson.String {
	//	log.Errorf("eth_sendRawTransaction result type error")
	//	return "", errors.New("eth_sendRawTransaction result type error")
	//}
	//return result.String(), nil
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := &message.ReqSignedTransaction{
		From:      from,
		To:        to,
		Amount:    amount,
		Nonce:     nonce,
		Time:      time,
		Hash:      hash,
		Signature: signature,
	}
	respTx, err := this.GreeterClient.SendSignedTransaction(ctx, in)
	if err != nil {
		log.Errorf("SendSignedTransaction failed, error = %s \n", err.Error())
		return "", err
	}
	return respTx.Hash, nil
}

// 发送需要线上签名的交易
func (this *Client) ktoSendTransaction(paraMap map[string]interface{}) (string, error) {
	trans := make(map[string]interface{})
	var temp interface{}
	var exist bool
	var fromAddr string
	var toAddr string
	var(
		err error
		amountInt *big.Int
		priv string
	)
	
	if temp, exist = paraMap["from"]; !exist {
		log.Errorf("from not found")
		return "", errors.New("from not found")
	} else {
		fromAddr = temp.(string)
		trans["from"] = fromAddr
	}
	
	if temp, exist = paraMap["to"]; !exist {
		log.Errorf("to not found")
		return "", errors.New("to not found")
	} else {
		toAddr = temp.(string)
		trans["to"] = toAddr
	}
	
	if temp, exist = paraMap["value"]; exist {
		amount := temp.(string)
		amountInt, err = ConvertKTOStringToK(amount)
		if err != nil {
			log.Errorf("convert amount failed, error %s", err.Error())
		}
		trans["value"] = amount
	}
	
	if temp, exist = paraMap["priv"]; exist {
		priv = temp.(string)
		trans["priv"] = priv
	}
	
	nonce, err := this.ktoGetAddressNonceAt(fromAddr)
	if err != nil {
		return "", err
	}
	
	in := &message.ReqTransaction{
		From:                 fromAddr,
		To:                   toAddr,
		Amount:               amountInt.Uint64(),
		Nonce:                nonce,
		Priv:                 priv,
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	respTx, err := this.GreeterClient.SendTransaction(ctx, in)
	if err != nil {
		log.Errorf("SendTransaction failed, error %s", err.Error())
		return "", nil
	}
	return respTx.Hash, nil
}

// 获取链上最大区块号
func (this *Client) GetMaxBlockNumber() (uint64, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := this.GreeterClient.GetMaxBlockNumber(ctx, &message.ReqMaxBlockNumber{})
	if err != nil {
		log.Errorf("get block number failed, err = %s \n", err.Error())
		return 0, err
	}
	return resp.MaxNumber, nil
}

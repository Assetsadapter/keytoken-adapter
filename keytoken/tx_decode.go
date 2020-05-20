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
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "github.com/Assetsadapter/keytoken-adapter/keytoken_txsigner"
    "github.com/blocktree/go-owcrypt"
    "github.com/shopspring/decimal"
    "strconv"
    
    "github.com/tidwall/gjson"
    
    //"log"
    "math/big"
    "sort"
    "sync"
    "time"
    
    "github.com/blocktree/openwallet/openwallet"
)

type EthTxExtPara struct {
    Data     string `json:"data"`
    GasLimit string `json:"gasLimit"`
}

func NewEthTxExtPara(j gjson.Result) *EthTxExtPara {
    obj := EthTxExtPara{}
    obj.GasLimit = j.Get("gasLimit").String()
    obj.Data = j.Get("data").String()
    return &obj
}

/*func (this *EthTxExtPara) GetGasLimit() (uint64, error) {
	gasLimit, err := strconv.ParseUint(removeOxFromHex(this.GasLimit), 16, 64)
	if err != nil {
		this.wm.Log.Std.Error("parse gas limit to uint64 failed, err=%v", err)
		return 0, err
	}
	return gasLimit, nil
}*/

const (
    ADRESS_STATIS_OVERDATED_TIME = 30
)

type AddrBalance struct {
    Address      string
    Balance      *big.Int
    TokenBalance *big.Int
    Index        int
}

func (this *AddrBalance) SetTokenBalance(b *big.Int) {
    this.TokenBalance = b
}

func (this *AddrBalance) GetAddress() string {
    return this.Address
}

func (this *AddrBalance) ValidTokenBalance() bool {
    if this.Balance == nil {
        return false
    }
    return true
}

type AddrBalanceInf interface {
    SetTokenBalance(b *big.Int)
    GetAddress() string
    ValidTokenBalance() bool
}

type AddressTxStatistic struct {
    Address          string
    TransactionCount *uint64
    LastModifiedTime *time.Time
    Valid            *int //如果valid指针指向的整形为0, 说明该地址已经被清理线程清理
    AddressLocker    *sync.Mutex
    //1. 地址级别, 不可并发广播交易, 造成nonce混乱
    //2. 地址级别, 不可广播, 读取nonce同时进行, 会造成nonce混乱
}

func (this *AddressTxStatistic) UpdateTime() {
    now := time.Now()
    this.LastModifiedTime = &now
}

type KtoTransactionDecoder struct {
    openwallet.TransactionDecoderBase
    AddrTxStatisMap *sync.Map
    //	DecoderLocker *sync.Mutex    //保护一些全局不可并发的操作, 如对AddrTxStatisMap的初始化
    wm *WalletManager //钱包管理者
}

func (this *KtoTransactionDecoder) GetTransactionCount2(address string) (*AddressTxStatistic, uint64, error) {
    now := time.Now()
    valid := 1
    t := AddressTxStatistic{
        LastModifiedTime: &now,
        AddressLocker:    new(sync.Mutex),
        Valid:            &valid,
        Address:          address,
        TransactionCount: new(uint64),
    }
    
    v, loaded := this.AddrTxStatisMap.LoadOrStore(address, t)
    //LoadOrStore返回后, AddressLocker加锁前, map中的nonce可能已经被清理了, 需要检查valid是否为1
    txStatis := v.(AddressTxStatistic)
    txStatis.AddressLocker.Lock()
    txStatis.AddressLocker.Unlock()
    if loaded {
        if *txStatis.Valid == 0 {
            return nil, 0, errors.New("the node is busy, try it again later. ")
        }
        txStatis.UpdateTime()
        return &txStatis, *txStatis.TransactionCount, nil
    }
    nonce, err := this.wm.GetNonceForAddress2(address)
    if err != nil {
        this.wm.Log.Std.Error("get nonce for address via rpc failed, err=%v", err)
        return nil, 0, err
    }
    *txStatis.TransactionCount = nonce
    return &txStatis, *txStatis.TransactionCount, nil
}

func (this *KtoTransactionDecoder) GetTransactionCount(address string) (uint64, error) {
    if this.AddrTxStatisMap == nil {
        return 0, errors.New("map should be initialized before using.")
    }
    
    v, exist := this.AddrTxStatisMap.Load(address)
    if !exist {
        return 0, errors.New("no records found to the key passed through.")
    }
    
    txStatis := v.(AddressTxStatistic)
    return *txStatis.TransactionCount, nil
}

func (this *KtoTransactionDecoder) SetTransactionCount(address string, transactionCount uint64) error {
    if this.AddrTxStatisMap == nil {
        return errors.New("map should be initialized before using.")
    }
    
    v, exist := this.AddrTxStatisMap.Load(address)
    if !exist {
        return errors.New("no records found to the key passed through.")
    }
    
    now := time.Now()
    valid := 1
    txStatis := AddressTxStatistic{
        TransactionCount: &transactionCount,
        LastModifiedTime: &now,
        AddressLocker:    new(sync.Mutex),
        Valid:            &valid,
        Address:          address,
    }
    
    if exist {
        txStatis.AddressLocker = v.(AddressTxStatistic).AddressLocker
    } else {
        txStatis.AddressLocker = &sync.Mutex{}
    }
    
    this.AddrTxStatisMap.Store(address, txStatis)
    return nil
}

func (this *KtoTransactionDecoder) RemoveOutdatedAddrStatic() {
    addrStatisList := make([]AddressTxStatistic, 0)
    this.AddrTxStatisMap.Range(func(k, v interface{}) bool {
        addrStatis := v.(AddressTxStatistic)
        if addrStatis.LastModifiedTime.Before(time.Now().Add(-1 * (ADRESS_STATIS_OVERDATED_TIME * time.Minute))) {
            addrStatisList = append(addrStatisList, addrStatis)
        }
        return true
    })
    
    clear := func(statis *AddressTxStatistic) {
        statis.AddressLocker.Lock()
        defer statis.AddressLocker.Unlock()
        if statis.LastModifiedTime.Before(time.Now().Add(-1 * (ADRESS_STATIS_OVERDATED_TIME * time.Minute))) {
            *statis.Valid = 0
            this.AddrTxStatisMap.Delete(statis.Address)
        }
    }
    
    for i, _ := range addrStatisList {
        clear(&addrStatisList[i])
    }
}

func (this *KtoTransactionDecoder) RunClearAddrStatic() {
    go func() {
        for {
            time.Sleep(5 * time.Minute)
            this.RemoveOutdatedAddrStatic()
        }
    }()
}

func (this *KtoTransactionDecoder) GetRawTransactionFeeRate() (feeRate string, unit string, err error) {
    return "0", "Gas", nil
}

func VerifyRawTransaction(rawTx *openwallet.RawTransaction) error {
    if len(rawTx.To) != 1 {
        //this.wm.Log.Error("only one to address can be set.")
        return errors.New("only one to address can be set.")
    }
    
    return nil
}

//NewTransactionDecoder 交易单解析器
func NewTransactionDecoder(wm *WalletManager) *KtoTransactionDecoder {
    decoder := KtoTransactionDecoder{}
    //	decoder.DecoderLocker = new(sync.Mutex)
    decoder.wm = wm
    decoder.AddrTxStatisMap = new(sync.Map)
    decoder.RunClearAddrStatic()
    return &decoder
}

func (this *KtoTransactionDecoder) CreateSimpleRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction, tmpNonce *uint64) error {
    
    var (
        accountID       = rawTx.Account.AccountID
        findAddrBalance *AddrBalance
        feeInfo         *txFeeInfo
    )
    
    //check交易交易单基本字段
    err := VerifyRawTransaction(rawTx)
    if err != nil {
        return err
    }
    
    //获取wallet
    addresses, err := wrapper.GetAddressList(0, -1,
        "AccountID", accountID)
    if err != nil {
        return openwallet.NewError(openwallet.ErrAddressNotFound, err.Error())
    }
    
    if len(addresses) == 0 {
        return openwallet.Errorf(openwallet.ErrAccountNotAddress, "[%s] have not addresses", accountID)
    }
    
    searchAddrs := make([]string, 0)
    for _, address := range addresses {
        searchAddrs = append(searchAddrs, address.Address)
    }
    
    addrBalanceArray, err := this.wm.Blockscanner.GetBalanceByAddress(searchAddrs...)
    if err != nil {
        return openwallet.NewError(openwallet.ErrCallFullNodeAPIFailed, err.Error())
    }
    
    var amountStr, to string
    for k, v := range rawTx.To {
        to = k
        amountStr = v
        break
    }
    
    amount, _ := ConvertKTOStringToK(amountStr)
    
    //地址余额从大到小排序
    sort.Slice(addrBalanceArray, func(i int, j int) bool {
        a_amount, _ := decimal.NewFromString(addrBalanceArray[i].Balance)
        b_amount, _ := decimal.NewFromString(addrBalanceArray[j].Balance)
        if a_amount.LessThan(b_amount) {
            return true
        } else {
            return false
        }
    })
    
    for _, addrBalance := range addrBalanceArray {
        
        //检查余额是否超过最低转账
        addrBalance_BI, _ := ConvertKTOStringToK(addrBalance.Balance)
        
        //计算手续费
        feeInfo, err = this.wm.GetTransactionFeeEstimated(addrBalance.Address, to, amount, "")
        if err != nil {
            this.wm.Log.Std.Error("GetTransactionFeeEstimated from[%v] -> to[%v] failed, err=%v", addrBalance.Address, to, err)
            continue
        }
        
        if rawTx.FeeRate != "" {
            feeInfo.GasPrice, _ = ConvertKTOStringToK(rawTx.FeeRate)
            feeInfo.CalcFee()
        }
        
        //总消耗数量 = 转账数量 + 手续费
        totalAmount := new(big.Int)
        totalAmount.Add(amount, feeInfo.Fee)
        
        if addrBalance_BI.Cmp(totalAmount) < 0 {
            continue
        }
        
        //只要找到一个合适使用的地址余额就停止遍历
        findAddrBalance = &AddrBalance{Address: addrBalance.Address, Balance: addrBalance_BI}
        break
    }
    
    if findAddrBalance == nil {
        return openwallet.Errorf(openwallet.ErrInsufficientBalanceOfAccount, "the balance: %s is not enough", amountStr)
    }
    
    //最后创建交易单
    createTxErr := this.createRawTransaction(
        wrapper,
        rawTx,
        findAddrBalance,
        feeInfo,
        "",
        tmpNonce)
    if createTxErr != nil {
        return createTxErr
    }
    
    return nil
}

//CreateRawTransaction 创建交易单
func (this *KtoTransactionDecoder) CreateRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {
    return this.CreateSimpleRawTransaction(wrapper, rawTx, nil)
}

//SignRawTransaction 签名交易单
func (this *KtoTransactionDecoder) SignRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {
    
    //check交易交易单基本字段
    err := VerifyRawTransaction(rawTx)
    if err != nil {
        this.wm.Log.Std.Error("Verify raw tx failed, err=%v", err)
        return err
    }
    
    if rawTx.Signatures == nil || len(rawTx.Signatures) == 0 {
        return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "transaction signature is empty")
    }
    
    key, err := wrapper.HDKey()
    if err != nil {
        this.wm.Log.Error("get HDKey from wallet wrapper failed, err=%v", err)
        return err
    }
    
    if _, exist := rawTx.Signatures[rawTx.Account.AccountID]; !exist {
        this.wm.Log.Std.Error("wallet[%v] signature not found ", rawTx.Account.AccountID)
        return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "wallet signature not found ")
    }
    
    if len(rawTx.Signatures[rawTx.Account.AccountID]) != 1 {
        this.wm.Log.Error("signature failed in account[%v].", rawTx.Account.AccountID)
        return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "signature failed in account.")
    }
    
    signnode := rawTx.Signatures[rawTx.Account.AccountID][0]
    fromAddr := signnode.Address
    
    childKey, _ := key.DerivedKeyWithPath(fromAddr.HDPath, this.wm.Config.CurveType)
    keyBytes, err := childKey.GetPrivateKeyBytes()
    if err != nil {
        this.wm.Log.Error("get private key bytes, err=", err)
        return openwallet.NewError(openwallet.ErrSignRawTransactionFailed, err.Error())
    }
    //message, err := hex.DecodeString(signnode.Message)
    tx := keytoken_txsigner.Transaction{}
    err = json.Unmarshal([]byte(signnode.Message), &tx)
    if err != nil {
        return err
    }
    sign, e := owcrypt.Signature(keyBytes, nil, 0, tx.Hash, 32, this.wm.CurveType())
    if e != owcrypt.SUCCESS {
        return errors.New(fmt.Sprintf("signature failed!"))
    }
    tx.Signature = sign
    
    signnode.Signature = hex.EncodeToString(tx.Signature)
    
    this.wm.Log.Debug("** message:", signnode.Message)
    this.wm.Log.Debug("** Signature:", signnode.Signature)
    
    return nil
}

func (this *KtoTransactionDecoder) SubmitSimpleRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) (*openwallet.Transaction, error) {
    //check交易交易单基本字段
    err := VerifyRawTransaction(rawTx)
    if err != nil {
        this.wm.Log.Std.Error("Verify raw tx failed, err=%v", err)
        return nil, err
    }
    if len(rawTx.Signatures) != 1 {
        this.wm.Log.Std.Error("len of signatures error. ")
        return nil, openwallet.Errorf(openwallet.ErrSubmitRawTransactionFailed, "len of signatures error. ")
    }
    
    if _, exist := rawTx.Signatures[rawTx.Account.AccountID]; !exist {
        this.wm.Log.Std.Error("wallet[%v] signature not found ", rawTx.Account.AccountID)
        return nil, openwallet.Errorf(openwallet.ErrSubmitRawTransactionFailed, "wallet signature not found ")
    }
    
    from := rawTx.Signatures[rawTx.Account.AccountID][0].Address.Address
    sig := rawTx.Signatures[rawTx.Account.AccountID][0].Signature
    
    this.wm.Log.Debug("rawTx.ExtParam:", rawTx.ExtParam)
    
    txStatis, _, err := this.GetTransactionCount2(from)
    err = func() error {
        txStatis.AddressLocker.Lock()
        defer txStatis.AddressLocker.Unlock()
        signBytes, err := hex.DecodeString(sig)
        if err != nil {
            this.wm.Log.Std.Error("signal decode to byte error = %s", err.Error())
            return err
        }
        
        var tx keytoken_txsigner.Transaction
        err = json.Unmarshal([]byte(rawTx.Signatures[rawTx.Account.AccountID][0].Message), &tx)
        if err != nil {
            this.wm.Log.Std.Error("unmarshal tx message failed, error = %s", err.Error())
            return err
        }
        // 检查交易的nonce值与本地存储的nonce值是否一致
        if tx.Nonce != *txStatis.TransactionCount {
            this.wm.Log.Std.Error("nonce out of dated, please try to start ur tx once again. ")
            return openwallet.Errorf(openwallet.ErrNonceInvaild, "nonce out of dated, please try to start ur tx once again. ")
        }
        txid, err := this.wm.WalletClient.ktoSendRawTransaction(
            string(tx.From.AddressToByte()),
            string(tx.To.AddressToByte()),
            tx.Amount,
            tx.Nonce,
            tx.Time,
            tx.Hash,
            signBytes)
        if err != nil {
            this.wm.Log.Std.Error("sent raw tx faild, err=%v", err)
            return openwallet.Errorf(openwallet.ErrSubmitRawTransactionFailed, "sent raw tx faild. unexpected error: %v", err)
        }
        
        rawTx.TxID = txid
        rawTx.IsSubmit = true
        
        // nonce值+1
        txStatis.UpdateTime()
        (*txStatis.TransactionCount)++
        
        this.wm.Log.Debug("transaction[", txid, "] has been sent out.")
        return nil
    }()
    
    if err != nil {
        this.wm.Log.Errorf("send raw transaction failed, err= %v", err)
        return nil, err
    }
    
    decimals := int32(0)
    if rawTx.Coin.IsContract {
        decimals = int32(rawTx.Coin.Contract.Decimals)
    } else {
        decimals = int32(this.wm.Decimal())
    }
    
    //记录一个交易单
    tx := &openwallet.Transaction{
        From:       rawTx.TxFrom,
        To:         rawTx.TxTo,
        Amount:     rawTx.TxAmount,
        Coin:       rawTx.Coin,
        TxID:       rawTx.TxID,
        Decimal:    decimals,
        AccountID:  rawTx.Account.AccountID,
        Fees:       rawTx.Fees,
        SubmitTime: time.Now().Unix(),
        TxType:     0,
    }
    
    tx.WxID = openwallet.GenTransactionWxID(tx)
    
    return tx, nil
}

//SendRawTransaction 广播交易单
func (this *KtoTransactionDecoder) SubmitRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) (*openwallet.Transaction, error) {
    return this.SubmitSimpleRawTransaction(wrapper, rawTx)
}

//VerifyRawTransaction 验证交易单，验证交易单并返回加入签名后的交易单
func (this *KtoTransactionDecoder) VerifyRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {
    //check交易交易单基本字段
    err := VerifyRawTransaction(rawTx)
    if err != nil {
        this.wm.Log.Std.Error("Verify raw tx failed, err=%v", err)
        return err
    }
    
    if rawTx.Signatures == nil || len(rawTx.Signatures) == 0 {
        //this.wm.Log.Std.Error("len of signatures error. ")
        return openwallet.Errorf(openwallet.ErrVerifyRawTransactionFailed, "transaction signature is empty")
    }
    
    accountSig, exist := rawTx.Signatures[rawTx.Account.AccountID]
    if !exist {
        this.wm.Log.Std.Error("wallet[%v] signature not found ", rawTx.Account.AccountID)
        return errors.New("wallet signature not found ")
    }
    
    if len(accountSig) == 0 {
        return openwallet.Errorf(openwallet.ErrVerifyRawTransactionFailed, "transaction signature is empty")
    }
    
    sig := accountSig[0].Signature
    msg := accountSig[0].Message
    pubkey := accountSig[0].Address.PublicKey
    
    this.wm.Log.Debug("-- pubkey:", pubkey)
    this.wm.Log.Debug("-- message:", msg)
    this.wm.Log.Debug("-- Signature:", sig)
    
    tx := keytoken_txsigner.Transaction{}
    err = json.Unmarshal([]byte(msg), &tx)
    if err != nil {
        return err
    }
    
    signature, err := hex.DecodeString(accountSig[0].Signature)
    if err != nil {
        return err
    }
    pubkeyByte, err := hex.DecodeString(pubkey)
    if err != nil {
        return err
    }
    publickKey := owcrypt.PointDecompress(pubkeyByte, this.wm.CurveType())
    publickKey = publickKey[1:len(publickKey)]
    ret := owcrypt.Verify(tx.From.AddrToPub(), nil, 0, tx.Hash, 32, signature[:], this.wm.CurveType())
    if ret != owcrypt.SUCCESS {
        errinfo := fmt.Sprintf("verify error, ret:%v\n", "0x"+strconv.FormatUint(uint64(ret), 16))
        fmt.Println(errinfo)
        return errors.New(errinfo)
    }
    
    return nil
}

//CreateSummaryRawTransaction 创建汇总交易，返回原始交易单数组
func (this *KtoTransactionDecoder) CreateSummaryRawTransaction(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransaction, error) {
    var (
        rawTxWithErrArray []*openwallet.RawTransactionWithError
        rawTxArray        = make([]*openwallet.RawTransaction, 0)
        err               error
    )
    rawTxWithErrArray, err = this.CreateSimpleSummaryRawTransaction(wrapper, sumRawTx)
    if err != nil {
        return nil, err
    }
    for _, rawTxWithErr := range rawTxWithErrArray {
        if rawTxWithErr.Error != nil {
            continue
        }
        rawTxArray = append(rawTxArray, rawTxWithErr.RawTx)
    }
    return rawTxArray, nil
}

//CreateSimpleSummaryRawTransaction 创建ETH汇总交易
func (this *KtoTransactionDecoder) CreateSimpleSummaryRawTransaction(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransactionWithError, error) {
    
    var (
        rawTxArray         = make([]*openwallet.RawTransactionWithError, 0)
        accountID          = sumRawTx.Account.AccountID
        minTransfer, _     = ConvertKTOStringToK(sumRawTx.MinTransfer)
        retainedBalance, _ = ConvertKTOStringToK(sumRawTx.RetainedBalance)
    )
    
    if minTransfer.Cmp(retainedBalance) < 0 {
        return nil, openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "mini transfer amount must be greater than address retained balance")
    }
    
    //获取wallet
    addresses, err := wrapper.GetAddressList(sumRawTx.AddressStartIndex, sumRawTx.AddressLimit,
        "AccountID", sumRawTx.Account.AccountID)
    if err != nil {
        return nil, err
    }
    
    if len(addresses) == 0 {
        return nil, openwallet.Errorf(openwallet.ErrAccountNotAddress, "[%s] have not addresses", accountID)
    }
    
    searchAddrs := make([]string, 0)
    for _, address := range addresses {
        searchAddrs = append(searchAddrs, address.Address)
    }
    
    addrBalanceArray, err := this.wm.Blockscanner.GetBalanceByAddress(searchAddrs...)
    if err != nil {
        return nil, err
    }
    
    for _, addrBalance := range addrBalanceArray {
        
        //检查余额是否超过最低转账
        addrBalance_BI, _ := ConvertKTOStringToK(addrBalance.Balance)
        
        if addrBalance_BI.Cmp(minTransfer) < 0 {
            continue
        }
        //计算汇总数量 = 余额 - 保留余额
        sumAmount_BI := new(big.Int)
        sumAmount_BI.Sub(addrBalance_BI, retainedBalance)
        
        //this.wm.Log.Debug("sumAmount:", sumAmount)
        //计算手续费
        fee, createErr := this.wm.GetTransactionFeeEstimated(addrBalance.Address, sumRawTx.SummaryAddress, sumAmount_BI, "")
        if createErr != nil {
            this.wm.Log.Std.Error("GetTransactionFeeEstimated from[%v] -> to[%v] failed, err=%v", addrBalance.Address, sumRawTx.SummaryAddress, createErr)
            return nil, createErr
        }
        
        if sumRawTx.FeeRate != "" {
            fee.GasPrice, createErr = ConvertKTOStringToK(sumRawTx.FeeRate) //ConvertToBigInt(rawTx.FeeRate, 16)
            if createErr != nil {
                this.wm.Log.Std.Error("fee rate passed through error, err=%v", createErr)
                return nil, createErr
            }
            fee.CalcFee()
        }
        
        //减去手续费
        sumAmount_BI.Sub(sumAmount_BI, fee.Fee)
        if sumAmount_BI.Cmp(big.NewInt(0)) <= 0 {
            continue
        }
        
        sumAmount, _ := ConverKStringToKtoDecimal(sumAmount_BI.String())
        fees, _ := ConverKStringToKtoDecimal(fee.Fee.String())
        
        this.wm.Log.Debugf("balance: %v", addrBalance.Balance)
        this.wm.Log.Debugf("fees: %v", fees)
        this.wm.Log.Debugf("sumAmount: %v", sumAmount)
        
        //创建一笔交易单
        rawTx := &openwallet.RawTransaction{
            Coin:    sumRawTx.Coin,
            Account: sumRawTx.Account,
            To: map[string]string{
                sumRawTx.SummaryAddress: sumAmount.StringFixed(this.wm.Decimal()),
            },
            Required: 1,
        }
        
        createTxErr := this.createRawTransaction(
            wrapper,
            rawTx,
            &AddrBalance{Address: addrBalance.Address, Balance: addrBalance_BI},
            fee,
            "",
            nil)
        rawTxWithErr := &openwallet.RawTransactionWithError{
            RawTx: rawTx,
            Error: createTxErr,
        }
        
        //创建成功，添加到队列
        rawTxArray = append(rawTxArray, rawTxWithErr)
        
    }
    
    return rawTxArray, nil
}

//createRawTransaction
func (this *KtoTransactionDecoder) createRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction, addrBalance *AddrBalance, fee *txFeeInfo, callData string, tmpNonce *uint64) *openwallet.Error {
    
    var (
        accountTotalSent = decimal.Zero
        txFrom           = make([]string, 0)
        txTo             = make([]string, 0)
        keySignList      = make([]*openwallet.KeySignature, 0)
        amountStr        string
        destination      string
        tx               *keytoken_txsigner.Transaction
    )
    
    for k, v := range rawTx.To {
        destination = k
        amountStr = v
        break
    }
    
    //计算账户的实际转账amount
    accountTotalSentAddresses, findErr := wrapper.GetAddressList(0, -1, "AccountID", rawTx.Account.AccountID, "Address", destination)
    if findErr != nil || len(accountTotalSentAddresses) == 0 {
        amountDec, _ := decimal.NewFromString(amountStr)
        accountTotalSent = accountTotalSent.Add(amountDec)
    }
    
    txFrom = []string{fmt.Sprintf("%s:%s", addrBalance.Address, amountStr)}
    txTo = []string{fmt.Sprintf("%s:%s", destination, amountStr)}
    
    rawTx.FeeRate = "0"
    rawTx.Fees = "0"
    rawTx.ExtParam = ""
    rawTx.TxAmount = accountTotalSent.StringFixed(this.wm.Decimal())
    rawTx.TxFrom = txFrom
    rawTx.TxTo = txTo
    
    addr, err := wrapper.GetAddress(addrBalance.Address)
    if err != nil {
        return openwallet.NewError(openwallet.ErrAccountNotAddress, err.Error())
    }
    
    var nonce uint64
    if tmpNonce == nil {
        _, txNonce, err := this.GetTransactionCount2(addrBalance.Address)
        if err != nil {
            this.wm.Log.Std.Error("GetTransactionCount2 failed, err=%v", err)
            return openwallet.NewError(openwallet.ErrNonceInvaild, err.Error())
        }
        nonce = txNonce
    } else {
        nonce = *tmpNonce
    }
    
    //构建ETH交易
    amount, _ := ConvertKTOStringToK(amountStr)
    
    totalAmount := new(big.Int)
    totalAmount.Add(amount, fee.Fee)
    if addrBalance.Balance.Cmp(totalAmount) < 0 {
        return openwallet.Errorf(openwallet.ErrInsufficientFees, "the [%s] balance: %s is not enough", rawTx.Coin.Symbol, amountStr)
    }
    
    tx = keytoken_txsigner.NewTransaction(nonce, amount.Uint64(), addrBalance.Address, destination)
    
    txstr, _ := json.Marshal(tx)
    this.wm.Log.Debug("**txStr:", string(txstr))
    
    if rawTx.Signatures == nil {
        rawTx.Signatures = make(map[string][]*openwallet.KeySignature)
    }
    
    signature := openwallet.KeySignature{
        EccType: this.wm.Config.CurveType,
        Nonce:   fmt.Sprintf("%d", nonce),
        Address: addr,
        Message: string(txstr),
    }
    keySignList = append(keySignList, &signature)
    
    rawTx.RawHex = hex.EncodeToString(tx.Hash)
    rawTx.Signatures[rawTx.Account.AccountID] = keySignList
    rawTx.IsBuilt = true
    
    return nil
}

// CreateSummaryRawTransactionWithError 创建汇总交易，返回能原始交易单数组（包含带错误的原始交易单）
func (this *KtoTransactionDecoder) CreateSummaryRawTransactionWithError(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransactionWithError, error) {
    return this.CreateSimpleSummaryRawTransaction(wrapper, sumRawTx)
}

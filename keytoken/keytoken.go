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
	"errors"
	"github.com/blocktree/openwallet/openwallet"
	//"log"
	"math/big"

	"github.com/blocktree/openwallet/log"
	"github.com/shopspring/decimal"
)

const (
	TRANS_AMOUNT_UNIT_LIST = `
	1: wei
	2: Kwei
	3: Mwei
	4: GWei
	5: microether
	6: milliether
	7: ether
	`
	TRANS_AMOUNT_UNIT_WEI          = 1
	TRANS_AMOUNT_UNIT_K_WEI        = 2
	TRANS_AMOUNT_UNIT_M_WEI        = 3
	TRANS_AMOUNT_UNIT_G_WEI        = 4
	TRANS_AMOUNT_UNIT_MICRO_ETHER  = 5
	TRANS_AMOUNT_UNIT_MILLIE_ETHER = 6
	TRNAS_AMOUNT_UNIT_ETHER        = 7
)

// 1KTO = 100000000000
const (
	Decimals = 11
)

// 将 KTO 转换为最小单位
func ConvertFloatStringToBigInt(amount string, decimals int) (*big.Int, error) {
	vDecimal, _ := decimal.NewFromString(amount)
	if decimals < 0 || decimals > 30 {
		return nil, errors.New("wrong decimal input through")
	}

	decimalInt := big.NewInt(1)
	for i := 0; i < decimals; i++ {
		decimalInt.Mul(decimalInt, big.NewInt(10))
	}

	d, _ := decimal.NewFromString(decimalInt.String())
	vDecimal = vDecimal.Mul(d)
	rst := new(big.Int)
	if _, valid := rst.SetString(vDecimal.String(), 10); !valid {
		log.Error("conver to big.int failed")
		return nil, errors.New("conver to big.int failed")
	}
	return rst, nil
}

// 将 KTO 转换为最小单位
func ConvertKTOStringToK(amount string) (*big.Int, error) {
	return ConvertFloatStringToBigInt(amount, Decimals)
}

// 最小单位余额转换为 KTO 单位
func ConvertAmountToFloatDecimal(amount string, decimals int) (decimal.Decimal, error) {
	d, err := decimal.NewFromString(amount)
	if err != nil {
		log.Error("convert string to decimal failed, err=", err)
		return d, err
	}
	return d.Shift(-int32(decimals)), nil
}

// 将最小单位的余额转换为 KTO 单位 接收 string 参数
func ConverKStringToKtoDecimal(amount string) (decimal.Decimal, error) {
	return ConvertAmountToFloatDecimal(amount, Decimals)
}

// 将 KTO 转换为最小单位的值 接收 decimal 参数
func ConverKtoDecimalToK(amount decimal.Decimal) (*big.Int, error) {
	return ConvertFloatStringToBigInt(amount.String(), Decimals)
}

func toHexBigIntForEtherTrans(value string, base int, unit int64) (*big.Int, error) {
	amount, err := ConvertToBigInt(value, base)
	if err != nil {
		//this.Log.Errorf("format transaction value failed, err = %v", err)
		return big.NewInt(0), err
	}

	switch unit {
	case TRANS_AMOUNT_UNIT_WEI:
	case TRANS_AMOUNT_UNIT_K_WEI:
		amount.Mul(amount, big.NewInt(1000))
	case TRANS_AMOUNT_UNIT_M_WEI:
		amount.Mul(amount, big.NewInt(1000*1000))
	case TRANS_AMOUNT_UNIT_G_WEI:
		amount.Mul(amount, big.NewInt(1000*1000*1000))
	case TRANS_AMOUNT_UNIT_MICRO_ETHER:
		amount.Mul(amount, big.NewInt(1000*1000*1000*1000))
	case TRANS_AMOUNT_UNIT_MILLIE_ETHER:
		amount.Mul(amount, big.NewInt(1000*1000*1000*1000*1000))
	case TRNAS_AMOUNT_UNIT_ETHER:
		amount.Mul(amount, big.NewInt(1000*1000*1000*1000*1000*1000))
	default:
		return big.NewInt(0), errors.New("wrong unit inputed")
	}

	return amount, nil
}

func (this *WalletManager) RecoverUnscannedTransactions(unscannedTxs []*openwallet.UnscanRecord) ([]BlockTransaction, error) {
	allTxs := make([]BlockTransaction, 0, len(unscannedTxs))
	for _, unscanned := range unscannedTxs {
		var tx BlockTransaction
		getTx, err := this.WalletClient.GetTxByHash(unscanned.TxID)
		if err != nil {
			return nil, err
		}
		tx = *getTx

		allTxs = append(allTxs, tx)
	}
	return allTxs, nil
}

//GetAssetsLogger 获取资产账户日志工具
func (this *WalletManager) GetAssetsLogger() *log.OWLogger {
	return this.Log
}

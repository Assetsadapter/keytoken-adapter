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
	"fmt"
	"github.com/astaxie/beego/config"
	"github.com/blocktree/openwallet/log"
	"math/big"
	"path/filepath"
	"testing"
)


var (
	tw *WalletManager
)

func init() {

	tw = testNewWalletManager()
}

func testNewWalletManager() *WalletManager {
	wm := NewWalletManager()

	//读取配置
	absFile := filepath.Join("conf", "conf.ini")
	//log.Debug("absFile:", absFile)
	c, err := config.NewConfig("ini", absFile)
	if err != nil {
		panic(err)
	}
	wm.LoadAssetsConfig(c)
	wm.WalletClient.Debug = true
	return wm
}

func TestFixGasLimit(t *testing.T) {
	fixGasLimitStr := "50000"
	fixGasLimit := new(big.Int)
	fixGasLimit.SetString(fixGasLimitStr, 10)
	fmt.Printf("fixGasLimit: %d\n", fixGasLimit.Int64())
}

func TestWalletManager_GetAddrBalance(t *testing.T) {
	wm := testNewWalletManager()
	balance, err := wm.WalletClient.GetAddrBalance("")
	if err != nil {
		t.Errorf("GetAddrBalance2 error: %v", err)
		return
	}
	ethB, _ := ConverKStringToKtoDecimal(balance.String())
	log.Infof("ethB: %v", ethB)
}
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
	"github.com/blocktree/openwallet/log"
	"fmt"
	"testing"
)

func TestWalletManager_KtoGetTransactionByHash(t *testing.T) {
	wm := testNewWalletManager()
	txid := "0x5d5c8e90621947c9f81ddbf97e2fc32436a936562faff404f71d6186bb801752"
	tx, err := wm.WalletClient.GetTxByHash(txid)
	if err != nil {
		t.Errorf("get transaction by has failed, err=%v", err)
		return
	}
	log.Infof("tx: %+v", tx)
}

func TestWalletManager_KtoGetBlockNumber(t *testing.T) {
	wm := testNewWalletManager()
	maxBlockHeight, err := wm.WalletClient.GetMaxBlockNumber()
	if err != nil {
		t.Errorf("GetMaxBlockNumber failed, err=%v", err)
		return
	}
	log.Infof("maxBlockHeight: %v", maxBlockHeight)
}

func TestClient_KtoGetBlockByNum(t *testing.T) {
	wm := testNewWalletManager()
	block, err := wm.WalletClient.KtoGetBlockByNum(243382)
	if err != nil {
		t.Errorf("GetBlockByNumber failed, err=%v", err)
		t.Fail()
	}
	fmt.Printf("Block has=%v", block)
}

func TestClient_GetTxByHash(t *testing.T) {
	wm := testNewWalletManager()
	tx, err := wm.WalletClient.GetTxByHash("")
	if err != nil {
		t.Errorf("GetTxByHash failed, err=%v", err)
		t.Fail()
	}
	fmt.Printf("Tx has=%v", tx)
}
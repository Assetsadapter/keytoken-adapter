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
	"github.com/Assetsadapter/keytoken-adapter/message"
	"google.golang.org/grpc"
	"testing"
)

func TestWalletManager_GetTokenBalanceByAddress(t *testing.T) {
	tm := NewWalletManager()
	baseAPI := "106.12.94.134:8545"

	connClient, err := grpc.Dial(baseAPI, grpc.WithInsecure())
	if err != nil {
		t.Errorf("dial remote rpc server fialed, error %s \n", err.Error())
	}

	client := &Client{Debug: true, GreeterClient: message.NewGreeterClient(connClient)}
	tm.WalletClient = client
	tm.Config.ChainID = 1

	addrs := []AddrBalanceInf{
		&AddrBalance{Address: "0xd1ffd8c9b59b6c2696ebdaa143c73226ea34d02c", Index: 0},
	}

	err = tm.GetTokenBalanceByAddress("0x4092678e4E78230F46A1534C0fbc8fA39780892B", addrs...)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
}

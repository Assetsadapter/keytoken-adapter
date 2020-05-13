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

func TestinitClient(t *testing.T) (*Client, error) {
	conn, err := grpc.Dial("106.12.94.134:8545", grpc.WithInsecure())
	if err != nil {
		t.Errorf("init client connect failed, error %s \n", err.Error())
		return nil, err
	}
	tw := &Client{
		Debug:         true,
		GreeterClient: message.NewGreeterClient(conn),
	}

	return tw, nil
}

func TestEthGetBlockNumber(t *testing.T) {

	tw, _ := TestinitClient(t)

	if r, err := tw.GetMaxBlockNumber(); err != nil {
		t.Errorf("GetAccountNet failed: %v\n", err)
	} else {
		t.Logf("GetAccountNet return: \n\t%+v\n", r)
	}
}

func TestClient_GetAddrBalance(t *testing.T) {
	addr := ""

	tw, _ := TestinitClient(t)
	if r, err := tw.GetAddrBalance(addr); err != nil {
		t.Errorf("GetAddrBalance failed: %v\n", err)
	} else {
		t.Logf("GetAddrBalance result:\n\t%+v\n", r)
	}
}

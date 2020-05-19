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
	"testing"
)

func TestAddressDecoder_PublicKeyToAddress(t *testing.T) {
	pub, _ := hex.DecodeString("0e98bd751a030dd9355f8cee728e6cdde65536ab83784683d8299606bbdfd09b")

	decoder := AddressDecoder{}

	addr, err := decoder.PublicKeyToAddress(pub, false)
	if err != nil {
		t.Errorf("AddressDecode failed unexpected error: %v\n", err)
		return
	}
	t.Logf("addr: %s", addr)
}

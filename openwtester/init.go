package openwtester

import (
	"github.com/Assetsadapter/keytoken-adapter/keytoken"
	"github.com/blocktree/openwallet/log"
	"github.com/blocktree/openwallet/openw"
)

func init() {
	//注册钱包管理工具
	log.Notice("Wallet Manager Load Successfully.")
	openw.RegAssets(keytoken.Symbol, keytoken.NewWalletManager())
}

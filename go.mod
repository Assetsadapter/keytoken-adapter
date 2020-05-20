module github.com/Assetsadapter/keytoken-adapter

go 1.12

require (
	github.com/asdine/storm v2.1.2+incompatible
	github.com/astaxie/beego v1.11.1
	github.com/blocktree/go-owcdrivers v1.0.12
	github.com/blocktree/go-owcrypt v1.0.1
	github.com/blocktree/openwallet v1.5.5
	github.com/golang/protobuf v1.4.1
	github.com/shopspring/decimal v0.0.0-20180709203117-cd690d0c9e24
	github.com/stretchr/testify v1.4.0 // indirect
	github.com/tidwall/gjson v1.2.1
	golang.org/x/crypto v0.0.0-20190404164418-38d8ce5564a5
	golang.org/x/sys v0.0.0-20190813064441-fde4db37ae7a // indirect
	google.golang.org/grpc v1.29.1
)

replace github.com/blocktree/openwallet v1.5.5 => github.com/Assetsadapter/openwallet v1.5.5-kto-v

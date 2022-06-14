module vmess_test

go 1.18

require (
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/sagernet/sing v0.0.0-20220614091938-64835a637bdc
	github.com/sagernet/sing-vmess v0.0.0
	github.com/stretchr/testify v1.7.2
	github.com/v2fly/v2ray-core/v5 v5.0.7
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e
)

replace github.com/sagernet/sing-vmess => ../

require (
	github.com/adrg/xdg v0.4.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20220411075957-e3b120b3f5fb // indirect
	github.com/v2fly/ss-bloomring v0.0.0-20210312155135-28617310f63e // indirect
	golang.org/x/sys v0.0.0-20220610221304-9f5ed59c137d // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

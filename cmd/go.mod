module github.com/paul-lee-attorney/fabric-2.1-gm/cmd

go 1.14

replace github.com/paul-lee-attorney/fabric-2.1-gm => ./../

replace github.com/paul-lee-attorney/gm => ./../../gm

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.2 // indirect
	github.com/hyperledger/fabric v2.1.1+incompatible
	github.com/hyperledger/fabric-amcl v0.0.0-20200424173818-327c9e2cf77a // indirect
	github.com/hyperledger/fabric-protos-go v0.0.0-20201028172056-a3136dde2354
	github.com/paul-lee-attorney/fabric-2.1-gm/bccsp v0.0.0-20201107143039-41236449d349
	github.com/paul-lee-attorney/gm v0.0.0-20201014053731-c3ade66b8a26
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.6.1
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897 // indirect
	google.golang.org/grpc v1.33.2 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v2 v2.3.0
)

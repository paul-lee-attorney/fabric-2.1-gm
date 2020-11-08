module github.com/paul-lee-attorney/fabric-2.1-gm

go 1.14

replace github.com/paul-lee-attorney/gm => ../gm

require (
	github.com/hyperledger/fabric v2.1.1+incompatible
	github.com/hyperledger/fabric-protos-go v0.0.0-20201028172056-a3136dde2354
	github.com/paul-lee-attorney/gm v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.4.0
	github.com/sykesm/zap-logfmt v0.0.4
	go.uber.org/zap v1.16.0
	google.golang.org/grpc v1.33.2
)

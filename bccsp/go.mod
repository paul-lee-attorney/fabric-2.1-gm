module github.com/paul-lee-attorney/fabric-2.1-gm/bccsp

go 1.14

replace github.com/paul-lee-attorney/fabric-2.1-gm => ./../

replace github.com/paul-lee-attorney/gm => ./../../gm

require (
	github.com/golang/protobuf v1.4.3
	github.com/hyperledger/fabric v2.1.1+incompatible
	github.com/hyperledger/fabric-amcl v0.0.0-20200424173818-327c9e2cf77a
	github.com/miekg/pkcs11 v1.0.3
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/paul-lee-attorney/fabric-2.1-gm v0.0.0-20201015142212-5dc35cb1f9b5
	github.com/paul-lee-attorney/gm v0.0.0-20201014053731-c3ade66b8a26
	github.com/pkg/errors v0.9.1
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
)

module github.com/paul-lee-attorney/fabric-2.1-gm

go 1.14

replace github.com/paul-lee-attorney/gm => ../gm

require (
	github.com/Knetic/govaluate v3.0.0+incompatible
	github.com/Shopify/sarama v1.27.2
	github.com/VictoriaMetrics/fastcache v1.5.7
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/docker v17.12.0-ce-rc1.0.20200505174321-1655290016ac+incompatible
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/fsouza/go-dockerclient v1.6.6
	github.com/golang/protobuf v1.4.2
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0
	github.com/hashicorp/go-version v1.2.1
	github.com/hyperledger/fabric v2.1.1+incompatible
	github.com/hyperledger/fabric-amcl v0.0.0-20200424173818-327c9e2cf77a
	github.com/hyperledger/fabric-chaincode-go v0.0.0-20200728190242-9b3ae92d8664
	github.com/hyperledger/fabric-lib-go v1.0.0
	github.com/hyperledger/fabric-protos-go v0.0.0-20201028172056-a3136dde2354
	github.com/mitchellh/mapstructure v1.1.2
	github.com/onsi/ginkgo v1.12.1
	github.com/onsi/gomega v1.10.3
	github.com/paul-lee-attorney/gm v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/sykesm/zap-logfmt v0.0.4
	github.com/syndtr/goleveldb v1.0.0
	github.com/tedsuo/ifrit v0.0.0-20191009134036-9a97d0632f00
	github.com/tjfoc/gmsm v1.3.2
	github.com/willf/bitset v1.1.11
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	google.golang.org/grpc v1.33.2
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v2 v2.3.0
)

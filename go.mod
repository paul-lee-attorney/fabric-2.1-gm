module github.com/paul-lee-attorney/fabric-2.1-gm

go 1.14

replace github.com/paul-lee-attorney/fabric-2.1-gm => ./

replace github.com/paul-lee-attorney/gm => ./../gm

require (
	code.cloudfoundry.org/clock v1.0.0
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
	github.com/Shopify/sarama v1.27.2
	github.com/VictoriaMetrics/fastcache v1.5.7
	github.com/davecgh/go-spew v1.1.1
	github.com/fsouza/go-dockerclient v1.6.6
	github.com/go-kit/kit v0.10.0
	github.com/golang/protobuf v1.4.3
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.2
	github.com/hashicorp/go-version v1.2.1
	github.com/hyperledger/fabric v2.1.1+incompatible
	github.com/hyperledger/fabric-amcl v0.0.0-20200424173818-327c9e2cf77a
	github.com/hyperledger/fabric-chaincode-go v0.0.0-20200728190242-9b3ae92d8664
	github.com/hyperledger/fabric-lib-go v1.0.0
	github.com/hyperledger/fabric-protos-go v0.0.0-20201028172056-a3136dde2354
	github.com/kr/pretty v0.2.1
	github.com/mitchellh/mapstructure v1.3.3
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/paul-lee-attorney/fabric-2.1-gm/bccsp v0.0.0-20201029021235-ed7e7e225c83
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.8.0
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/sykesm/zap-logfmt v0.0.4
	github.com/syndtr/goleveldb v1.0.0
	github.com/tedsuo/ifrit v0.0.0-20191009134036-9a97d0632f00
	github.com/willf/bitset v1.1.11
	go.etcd.io/etcd v3.3.25+incompatible
	go.uber.org/zap v1.16.0
	golang.org/x/tools v0.0.0-20201028224754-2c115999a7f0
	google.golang.org/grpc v1.33.1
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/cheggaaa/pb.v1 v1.0.28
	gopkg.in/yaml.v2 v2.3.0
)

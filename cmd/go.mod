module github.com/paul-lee-attorney/fabric-2.1-gm/cmd

go 1.14

replace github.com/paul-lee-attorney/fabric-2.1-gm => ./../

replace github.com/paul-lee-attorney/gm => ./../../gm

require (
	github.com/golang/protobuf v1.4.3
	github.com/gorilla/handlers v1.5.1
	github.com/hyperledger/fabric v2.1.1+incompatible
	github.com/hyperledger/fabric-protos-go v0.0.0-20201028172056-a3136dde2354
	github.com/onsi/gomega v1.10.3
	github.com/paul-lee-attorney/fabric-2.1-gm/bccsp v0.0.0-20201106041934-3c289ea58f19
	github.com/paul-lee-attorney/gm v0.0.0-20201014053731-c3ade66b8a26
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	google.golang.org/grpc v1.33.2
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v2 v2.3.0
)

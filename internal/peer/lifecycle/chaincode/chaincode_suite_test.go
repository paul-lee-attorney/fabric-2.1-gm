/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package chaincode_test

import (
	"fmt"
	"os"
	"testing"

	pb "github.com/hyperledger/fabric-protos-go/peer"
	“github.com/paul-lee-attorney/fabric-2.1-gm/internal/peer/common"
	“github.com/paul-lee-attorney/fabric-2.1-gm/internal/peer/lifecycle/chaincode"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	msptesttools "github.com/paul-lee-attorney/fabric-2.1-gm/msp/mgmt/testtools"
)

//go:generate counterfeiter -o mock/writer.go -fake-name Writer . writer
type writer interface {
	chaincode.Writer
}

//go:generate counterfeiter -o mock/platform_registry.go -fake-name PlatformRegistry . platformRegistry
type platformRegistry interface {
	chaincode.PlatformRegistry
}

//go:generate counterfeiter -o mock/reader.go -fake-name Reader . reader
type reader interface {
	chaincode.Reader
}

//go:generate counterfeiter -o mock/endorser_client.go -fake-name EndorserClient . endorserClient
type endorserClient interface {
	chaincode.EndorserClient
}

//go:generate counterfeiter -o mock/signer.go -fake-name Signer . signer
type signer interface {
	chaincode.Signer
}

//go:generate counterfeiter -o mock/broadcast_client.go -fake-name BroadcastClient . broadcastClient
type broadcastClient interface {
	common.BroadcastClient
}

//go:generate counterfeiter -o mock/peer_deliver_client.go -fake-name PeerDeliverClient . peerDeliverClient
type peerDeliverClient interface {
	pb.DeliverClient
}

//go:generate counterfeiter -o mock/deliver.go -fake-name Deliver . deliver
type deliver interface {
	pb.Deliver_DeliverClient
}

func TestChaincode(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Chaincode Suite")
}

// TODO remove this?
func TestMain(m *testing.M) {
	err := msptesttools.LoadMSPSetupForTesting()
	if err != nil {
		panic(fmt.Sprintf("Fatal error when reading MSP config: %s", err))
	}
	os.Exit(m.Run())
}

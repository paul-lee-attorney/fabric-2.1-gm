/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package extcc_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/chaincode/extcc"
)

func TestExtcc(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Chaincode Suite")
}

//go:generate counterfeiter -o mock/ccstreamhandler.go --fake-name StreamHandler . StreamHandler
type chaincodeStreamHandler interface {
	extcc.StreamHandler
}

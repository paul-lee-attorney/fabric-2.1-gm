/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import (
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/decoration"
)

// NewDecorator creates a new decorator
func NewDecorator() decoration.Decorator {
	return &decorator{}
}

type decorator struct {
}

// Decorate decorates a chaincode input by changing it
func (d *decorator) Decorate(proposal *peer.Proposal, input *peer.ChaincodeInput) *peer.ChaincodeInput {
	return input
}

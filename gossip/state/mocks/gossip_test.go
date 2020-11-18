/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"testing"

	proto "github.com/hyperledger/fabric-protos-go/gossip"
	"github.com/paul-lee-attorney/fabric-2.1-gm/gossip/api"
	"github.com/paul-lee-attorney/fabric-2.1-gm/gossip/common"
	"github.com/paul-lee-attorney/fabric-2.1-gm/gossip/discovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGossipMock(t *testing.T) {
	g := GossipMock{}
	mkChan := func() <-chan *proto.GossipMessage {
		c := make(chan *proto.GossipMessage, 1)
		c <- &proto.GossipMessage{}
		return c
	}
	g.On("Accept", mock.Anything, false).Return(mkChan(), nil)
	a, b := g.Accept(func(o interface{}) bool {
		return true
	}, false)
	assert.Nil(t, b)
	assert.NotNil(t, a)
	assert.Panics(t, func() {
		g.SuspectPeers(func(identity api.PeerIdentityType) bool { return false })
	})
	assert.Panics(t, func() {
		g.Send(nil, nil)
	})
	assert.Panics(t, func() {
		g.Peers()
	})
	g.On("PeersOfChannel", mock.Anything).Return([]discovery.NetworkMember{})
	assert.Empty(t, g.PeersOfChannel(common.ChannelID("A")))

	assert.Panics(t, func() {
		g.UpdateMetadata([]byte{})
	})
	assert.Panics(t, func() {
		g.Gossip(nil)
	})
	assert.NotPanics(t, func() {
		g.UpdateLedgerHeight(0, common.ChannelID("A"))
		g.Stop()
		g.JoinChan(nil, common.ChannelID("A"))
	})
}

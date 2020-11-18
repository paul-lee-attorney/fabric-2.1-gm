/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"github.com/paul-lee-attorney/fabric-2.1-gm/gossip/common"
	"github.com/paul-lee-attorney/fabric-2.1-gm/gossip/protoext"
	"github.com/paul-lee-attorney/fabric-2.1-gm/gossip/util"
)

type sendFunc func(peer *RemotePeer, msg *protoext.SignedGossipMessage)
type waitFunc func(*RemotePeer) error

type ackSendOperation struct {
	snd        sendFunc
	waitForAck waitFunc
}

func newAckSendOperation(snd sendFunc, waitForAck waitFunc) *ackSendOperation {
	return &ackSendOperation{
		snd:        snd,
		waitForAck: waitForAck,
	}
}

func (aso *ackSendOperation) send(msg *protoext.SignedGossipMessage, minAckNum int, peers ...*RemotePeer) []SendResult {
	successAcks := 0
	results := []SendResult{}

	acks := make(chan SendResult, len(peers))
	// Send to all peers the message
	for _, p := range peers {
		go func(p *RemotePeer) {
			// Send the message to 'p'
			aso.snd(p, msg)
			// Wait for an ack from 'p', or get an error if timed out
			err := aso.waitForAck(p)
			acks <- SendResult{
				RemotePeer: *p,
				error:      err,
			}
		}(p)
	}
	for {
		ack := <-acks
		results = append(results, SendResult{
			error:      ack.error,
			RemotePeer: ack.RemotePeer,
		})
		if ack.error == nil {
			successAcks++
		}
		if successAcks == minAckNum || len(results) == len(peers) {
			break
		}
	}
	return results
}

func interceptAcks(nextHandler handler, remotePeerID common.PKIidType, pubSub *util.PubSub) func(*protoext.SignedGossipMessage) {
	return func(m *protoext.SignedGossipMessage) {
		if protoext.IsAck(m.GossipMessage) {
			topic := topicForAck(m.Nonce, remotePeerID)
			pubSub.Publish(topic, m.GetAck())
			return
		}
		nextHandler(m)
	}
}

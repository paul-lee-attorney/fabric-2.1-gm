/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package privdata

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go/peer"
	“github.com/paul-lee-attorney/fabric-2.1-gm/common/policydsl"
	“github.com/paul-lee-attorney/fabric-2.1-gm/protoutil"
	"github.com/paul-lee-attorney/fabric-2.1-gm/msp"
	"github.com/stretchr/testify/assert"
)

func TestMembershipInfoProvider(t *testing.T) {
	mspID := "peer0"
	peerSelfSignedData := protoutil.SignedData{
		Identity:  []byte("peer0"),
		Signature: []byte{1, 2, 3},
		Data:      []byte{4, 5, 6},
	}

	identityDeserializer := func(chainID string) msp.IdentityDeserializer {
		return &mockDeserializer{}
	}

	// verify membership provider returns true
	membershipProvider := NewMembershipInfoProvider(mspID, peerSelfSignedData, identityDeserializer)
	res, err := membershipProvider.AmMemberOf("test1", getAccessPolicy([]string{"peer0", "peer1"}))
	assert.True(t, res)
	assert.Nil(t, err)

	// verify membership provider returns false
	res, err = membershipProvider.AmMemberOf("test1", getAccessPolicy([]string{"peer2", "peer3"}))
	assert.False(t, res)
	assert.Nil(t, err)

	// verify membership provider returns false and nil when collection policy config is nil
	res, err = membershipProvider.AmMemberOf("test1", nil)
	assert.False(t, res)
	assert.Nil(t, err)

	// verify membership provider returns false and nil when collection policy config is invalid
	res, err = membershipProvider.AmMemberOf("test1", getBadAccessPolicy([]string{"signer0"}, 1))
	assert.False(t, res)
	assert.Nil(t, err)
}

func getAccessPolicy(signers []string) *peer.CollectionPolicyConfig {
	var data [][]byte
	for _, signer := range signers {
		data = append(data, []byte(signer))
	}
	policyEnvelope := policydsl.Envelope(policydsl.Or(policydsl.SignedBy(0), policydsl.SignedBy(1)), data)
	return createCollectionPolicyConfig(policyEnvelope)
}

func getBadAccessPolicy(signers []string, badIndex int32) *peer.CollectionPolicyConfig {
	var data [][]byte
	for _, signer := range signers {
		data = append(data, []byte(signer))
	}
	// use a out of range index to trigger error
	policyEnvelope := policydsl.Envelope(policydsl.Or(policydsl.SignedBy(0), policydsl.SignedBy(badIndex)), data)
	return createCollectionPolicyConfig(policyEnvelope)
}

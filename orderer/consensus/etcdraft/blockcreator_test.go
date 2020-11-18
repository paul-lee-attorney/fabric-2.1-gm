/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package etcdraft

import (
	"testing"

	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/flogging"
	"github.com/paul-lee-attorney/fabric-2.1-gm/protoutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func getSeedBlock() *cb.Block {
	seedBlock := protoutil.NewBlock(0, []byte("firsthash"))
	seedBlock.Data.Data = [][]byte{[]byte("somebytes")}
	return seedBlock
}

func TestCreateNextBlock(t *testing.T) {
	first := protoutil.NewBlock(0, []byte("firsthash"))
	bc := &blockCreator{
		hash:   protoutil.BlockHeaderHash(first.Header),
		number: first.Header.Number,
		logger: flogging.NewFabricLogger(zap.NewNop()),
	}

	second := bc.createNextBlock([]*cb.Envelope{{Payload: []byte("some other bytes")}})
	assert.Equal(t, first.Header.Number+1, second.Header.Number)
	assert.Equal(t, protoutil.BlockDataHash(second.Data), second.Header.DataHash)
	assert.Equal(t, protoutil.BlockHeaderHash(first.Header), second.Header.PreviousHash)

	third := bc.createNextBlock([]*cb.Envelope{{Payload: []byte("some other bytes")}})
	assert.Equal(t, second.Header.Number+1, third.Header.Number)
	assert.Equal(t, protoutil.BlockDataHash(third.Data), third.Header.DataHash)
	assert.Equal(t, protoutil.BlockHeaderHash(second.Header), third.Header.PreviousHash)
}

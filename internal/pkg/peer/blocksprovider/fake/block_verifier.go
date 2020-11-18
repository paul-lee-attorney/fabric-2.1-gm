// Code generated by counterfeiter. DO NOT EDIT.
package fake

import (
	"sync"

	commona "github.com/hyperledger/fabric-protos-go/common"
	"github.com/paul-lee-attorney/fabric-2.1-gm/gossip/common"
	"github.com/paul-lee-attorney/fabric-2.1-gm/internal/pkg/peer/blocksprovider"
)

type BlockVerifier struct {
	VerifyBlockStub        func(common.ChannelID, uint64, *commona.Block) error
	verifyBlockMutex       sync.RWMutex
	verifyBlockArgsForCall []struct {
		arg1 common.ChannelID
		arg2 uint64
		arg3 *commona.Block
	}
	verifyBlockReturns struct {
		result1 error
	}
	verifyBlockReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *BlockVerifier) VerifyBlock(arg1 common.ChannelID, arg2 uint64, arg3 *commona.Block) error {
	fake.verifyBlockMutex.Lock()
	ret, specificReturn := fake.verifyBlockReturnsOnCall[len(fake.verifyBlockArgsForCall)]
	fake.verifyBlockArgsForCall = append(fake.verifyBlockArgsForCall, struct {
		arg1 common.ChannelID
		arg2 uint64
		arg3 *commona.Block
	}{arg1, arg2, arg3})
	fake.recordInvocation("VerifyBlock", []interface{}{arg1, arg2, arg3})
	fake.verifyBlockMutex.Unlock()
	if fake.VerifyBlockStub != nil {
		return fake.VerifyBlockStub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.verifyBlockReturns
	return fakeReturns.result1
}

func (fake *BlockVerifier) VerifyBlockCallCount() int {
	fake.verifyBlockMutex.RLock()
	defer fake.verifyBlockMutex.RUnlock()
	return len(fake.verifyBlockArgsForCall)
}

func (fake *BlockVerifier) VerifyBlockCalls(stub func(common.ChannelID, uint64, *commona.Block) error) {
	fake.verifyBlockMutex.Lock()
	defer fake.verifyBlockMutex.Unlock()
	fake.VerifyBlockStub = stub
}

func (fake *BlockVerifier) VerifyBlockArgsForCall(i int) (common.ChannelID, uint64, *commona.Block) {
	fake.verifyBlockMutex.RLock()
	defer fake.verifyBlockMutex.RUnlock()
	argsForCall := fake.verifyBlockArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *BlockVerifier) VerifyBlockReturns(result1 error) {
	fake.verifyBlockMutex.Lock()
	defer fake.verifyBlockMutex.Unlock()
	fake.VerifyBlockStub = nil
	fake.verifyBlockReturns = struct {
		result1 error
	}{result1}
}

func (fake *BlockVerifier) VerifyBlockReturnsOnCall(i int, result1 error) {
	fake.verifyBlockMutex.Lock()
	defer fake.verifyBlockMutex.Unlock()
	fake.VerifyBlockStub = nil
	if fake.verifyBlockReturnsOnCall == nil {
		fake.verifyBlockReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.verifyBlockReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *BlockVerifier) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.verifyBlockMutex.RLock()
	defer fake.verifyBlockMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *BlockVerifier) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ blocksprovider.BlockVerifier = new(BlockVerifier)

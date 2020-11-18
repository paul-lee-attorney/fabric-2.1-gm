// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/paul-lee-attorney/fabric-2.1-gm/msp"
)

type ConvertiblePolicy struct {
	ConvertStub        func() (*common.SignaturePolicyEnvelope, error)
	convertMutex       sync.RWMutex
	convertArgsForCall []struct {
	}
	convertReturns struct {
		result1 *common.SignaturePolicyEnvelope
		result2 error
	}
	convertReturnsOnCall map[int]struct {
		result1 *common.SignaturePolicyEnvelope
		result2 error
	}
	EvaluateIdentitiesStub        func([]msp.Identity) error
	evaluateIdentitiesMutex       sync.RWMutex
	evaluateIdentitiesArgsForCall []struct {
		arg1 []msp.Identity
	}
	evaluateIdentitiesReturns struct {
		result1 error
	}
	evaluateIdentitiesReturnsOnCall map[int]struct {
		result1 error
	}
	EvaluateSignedDataStub        func([]*protoutil.SignedData) error
	evaluateSignedDataMutex       sync.RWMutex
	evaluateSignedDataArgsForCall []struct {
		arg1 []*protoutil.SignedData
	}
	evaluateSignedDataReturns struct {
		result1 error
	}
	evaluateSignedDataReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ConvertiblePolicy) Convert() (*common.SignaturePolicyEnvelope, error) {
	fake.convertMutex.Lock()
	ret, specificReturn := fake.convertReturnsOnCall[len(fake.convertArgsForCall)]
	fake.convertArgsForCall = append(fake.convertArgsForCall, struct {
	}{})
	fake.recordInvocation("Convert", []interface{}{})
	fake.convertMutex.Unlock()
	if fake.ConvertStub != nil {
		return fake.ConvertStub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.convertReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *ConvertiblePolicy) ConvertCallCount() int {
	fake.convertMutex.RLock()
	defer fake.convertMutex.RUnlock()
	return len(fake.convertArgsForCall)
}

func (fake *ConvertiblePolicy) ConvertCalls(stub func() (*common.SignaturePolicyEnvelope, error)) {
	fake.convertMutex.Lock()
	defer fake.convertMutex.Unlock()
	fake.ConvertStub = stub
}

func (fake *ConvertiblePolicy) ConvertReturns(result1 *common.SignaturePolicyEnvelope, result2 error) {
	fake.convertMutex.Lock()
	defer fake.convertMutex.Unlock()
	fake.ConvertStub = nil
	fake.convertReturns = struct {
		result1 *common.SignaturePolicyEnvelope
		result2 error
	}{result1, result2}
}

func (fake *ConvertiblePolicy) ConvertReturnsOnCall(i int, result1 *common.SignaturePolicyEnvelope, result2 error) {
	fake.convertMutex.Lock()
	defer fake.convertMutex.Unlock()
	fake.ConvertStub = nil
	if fake.convertReturnsOnCall == nil {
		fake.convertReturnsOnCall = make(map[int]struct {
			result1 *common.SignaturePolicyEnvelope
			result2 error
		})
	}
	fake.convertReturnsOnCall[i] = struct {
		result1 *common.SignaturePolicyEnvelope
		result2 error
	}{result1, result2}
}

func (fake *ConvertiblePolicy) EvaluateIdentities(arg1 []msp.Identity) error {
	var arg1Copy []msp.Identity
	if arg1 != nil {
		arg1Copy = make([]msp.Identity, len(arg1))
		copy(arg1Copy, arg1)
	}
	fake.evaluateIdentitiesMutex.Lock()
	ret, specificReturn := fake.evaluateIdentitiesReturnsOnCall[len(fake.evaluateIdentitiesArgsForCall)]
	fake.evaluateIdentitiesArgsForCall = append(fake.evaluateIdentitiesArgsForCall, struct {
		arg1 []msp.Identity
	}{arg1Copy})
	fake.recordInvocation("EvaluateIdentities", []interface{}{arg1Copy})
	fake.evaluateIdentitiesMutex.Unlock()
	if fake.EvaluateIdentitiesStub != nil {
		return fake.EvaluateIdentitiesStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.evaluateIdentitiesReturns
	return fakeReturns.result1
}

func (fake *ConvertiblePolicy) EvaluateIdentitiesCallCount() int {
	fake.evaluateIdentitiesMutex.RLock()
	defer fake.evaluateIdentitiesMutex.RUnlock()
	return len(fake.evaluateIdentitiesArgsForCall)
}

func (fake *ConvertiblePolicy) EvaluateIdentitiesCalls(stub func([]msp.Identity) error) {
	fake.evaluateIdentitiesMutex.Lock()
	defer fake.evaluateIdentitiesMutex.Unlock()
	fake.EvaluateIdentitiesStub = stub
}

func (fake *ConvertiblePolicy) EvaluateIdentitiesArgsForCall(i int) []msp.Identity {
	fake.evaluateIdentitiesMutex.RLock()
	defer fake.evaluateIdentitiesMutex.RUnlock()
	argsForCall := fake.evaluateIdentitiesArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ConvertiblePolicy) EvaluateIdentitiesReturns(result1 error) {
	fake.evaluateIdentitiesMutex.Lock()
	defer fake.evaluateIdentitiesMutex.Unlock()
	fake.EvaluateIdentitiesStub = nil
	fake.evaluateIdentitiesReturns = struct {
		result1 error
	}{result1}
}

func (fake *ConvertiblePolicy) EvaluateIdentitiesReturnsOnCall(i int, result1 error) {
	fake.evaluateIdentitiesMutex.Lock()
	defer fake.evaluateIdentitiesMutex.Unlock()
	fake.EvaluateIdentitiesStub = nil
	if fake.evaluateIdentitiesReturnsOnCall == nil {
		fake.evaluateIdentitiesReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.evaluateIdentitiesReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *ConvertiblePolicy) EvaluateSignedData(arg1 []*protoutil.SignedData) error {
	var arg1Copy []*protoutil.SignedData
	if arg1 != nil {
		arg1Copy = make([]*protoutil.SignedData, len(arg1))
		copy(arg1Copy, arg1)
	}
	fake.evaluateSignedDataMutex.Lock()
	ret, specificReturn := fake.evaluateSignedDataReturnsOnCall[len(fake.evaluateSignedDataArgsForCall)]
	fake.evaluateSignedDataArgsForCall = append(fake.evaluateSignedDataArgsForCall, struct {
		arg1 []*protoutil.SignedData
	}{arg1Copy})
	fake.recordInvocation("EvaluateSignedData", []interface{}{arg1Copy})
	fake.evaluateSignedDataMutex.Unlock()
	if fake.EvaluateSignedDataStub != nil {
		return fake.EvaluateSignedDataStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.evaluateSignedDataReturns
	return fakeReturns.result1
}

func (fake *ConvertiblePolicy) EvaluateSignedDataCallCount() int {
	fake.evaluateSignedDataMutex.RLock()
	defer fake.evaluateSignedDataMutex.RUnlock()
	return len(fake.evaluateSignedDataArgsForCall)
}

func (fake *ConvertiblePolicy) EvaluateSignedDataCalls(stub func([]*protoutil.SignedData) error) {
	fake.evaluateSignedDataMutex.Lock()
	defer fake.evaluateSignedDataMutex.Unlock()
	fake.EvaluateSignedDataStub = stub
}

func (fake *ConvertiblePolicy) EvaluateSignedDataArgsForCall(i int) []*protoutil.SignedData {
	fake.evaluateSignedDataMutex.RLock()
	defer fake.evaluateSignedDataMutex.RUnlock()
	argsForCall := fake.evaluateSignedDataArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ConvertiblePolicy) EvaluateSignedDataReturns(result1 error) {
	fake.evaluateSignedDataMutex.Lock()
	defer fake.evaluateSignedDataMutex.Unlock()
	fake.EvaluateSignedDataStub = nil
	fake.evaluateSignedDataReturns = struct {
		result1 error
	}{result1}
}

func (fake *ConvertiblePolicy) EvaluateSignedDataReturnsOnCall(i int, result1 error) {
	fake.evaluateSignedDataMutex.Lock()
	defer fake.evaluateSignedDataMutex.Unlock()
	fake.EvaluateSignedDataStub = nil
	if fake.evaluateSignedDataReturnsOnCall == nil {
		fake.evaluateSignedDataReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.evaluateSignedDataReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *ConvertiblePolicy) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.convertMutex.RLock()
	defer fake.convertMutex.RUnlock()
	fake.evaluateIdentitiesMutex.RLock()
	defer fake.evaluateIdentitiesMutex.RUnlock()
	fake.evaluateSignedDataMutex.RLock()
	defer fake.evaluateSignedDataMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *ConvertiblePolicy) recordInvocation(key string, args []interface{}) {
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

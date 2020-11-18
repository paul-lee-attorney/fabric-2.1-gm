// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	"github.com/paul-lee-attorney/fabric-2.1-gm/msp"
)

type IdentityDeserializerManager struct {
	DeserializerStub        func(string) (msp.IdentityDeserializer, error)
	deserializerMutex       sync.RWMutex
	deserializerArgsForCall []struct {
		arg1 string
	}
	deserializerReturns struct {
		result1 msp.IdentityDeserializer
		result2 error
	}
	deserializerReturnsOnCall map[int]struct {
		result1 msp.IdentityDeserializer
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *IdentityDeserializerManager) Deserializer(arg1 string) (msp.IdentityDeserializer, error) {
	fake.deserializerMutex.Lock()
	ret, specificReturn := fake.deserializerReturnsOnCall[len(fake.deserializerArgsForCall)]
	fake.deserializerArgsForCall = append(fake.deserializerArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("Deserializer", []interface{}{arg1})
	fake.deserializerMutex.Unlock()
	if fake.DeserializerStub != nil {
		return fake.DeserializerStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.deserializerReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *IdentityDeserializerManager) DeserializerCallCount() int {
	fake.deserializerMutex.RLock()
	defer fake.deserializerMutex.RUnlock()
	return len(fake.deserializerArgsForCall)
}

func (fake *IdentityDeserializerManager) DeserializerCalls(stub func(string) (msp.IdentityDeserializer, error)) {
	fake.deserializerMutex.Lock()
	defer fake.deserializerMutex.Unlock()
	fake.DeserializerStub = stub
}

func (fake *IdentityDeserializerManager) DeserializerArgsForCall(i int) string {
	fake.deserializerMutex.RLock()
	defer fake.deserializerMutex.RUnlock()
	argsForCall := fake.deserializerArgsForCall[i]
	return argsForCall.arg1
}

func (fake *IdentityDeserializerManager) DeserializerReturns(result1 msp.IdentityDeserializer, result2 error) {
	fake.deserializerMutex.Lock()
	defer fake.deserializerMutex.Unlock()
	fake.DeserializerStub = nil
	fake.deserializerReturns = struct {
		result1 msp.IdentityDeserializer
		result2 error
	}{result1, result2}
}

func (fake *IdentityDeserializerManager) DeserializerReturnsOnCall(i int, result1 msp.IdentityDeserializer, result2 error) {
	fake.deserializerMutex.Lock()
	defer fake.deserializerMutex.Unlock()
	fake.DeserializerStub = nil
	if fake.deserializerReturnsOnCall == nil {
		fake.deserializerReturnsOnCall = make(map[int]struct {
			result1 msp.IdentityDeserializer
			result2 error
		})
	}
	fake.deserializerReturnsOnCall[i] = struct {
		result1 msp.IdentityDeserializer
		result2 error
	}{result1, result2}
}

func (fake *IdentityDeserializerManager) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.deserializerMutex.RLock()
	defer fake.deserializerMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *IdentityDeserializerManager) recordInvocation(key string, args []interface{}) {
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

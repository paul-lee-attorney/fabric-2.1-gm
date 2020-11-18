// Code generated by counterfeiter. DO NOT EDIT.
package fake

import (
	"sync"

	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/chaincode/lifecycle"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/common/ccprovider"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger"
)

type Support struct {
	ChaincodeEndorsementInfoStub        func(string, string, ledger.QueryExecutor) (*lifecycle.ChaincodeEndorsementInfo, error)
	chaincodeEndorsementInfoMutex       sync.RWMutex
	chaincodeEndorsementInfoArgsForCall []struct {
		arg1 string
		arg2 string
		arg3 ledger.QueryExecutor
	}
	chaincodeEndorsementInfoReturns struct {
		result1 *lifecycle.ChaincodeEndorsementInfo
		result2 error
	}
	chaincodeEndorsementInfoReturnsOnCall map[int]struct {
		result1 *lifecycle.ChaincodeEndorsementInfo
		result2 error
	}
	CheckACLStub        func(string, *peer.SignedProposal) error
	checkACLMutex       sync.RWMutex
	checkACLArgsForCall []struct {
		arg1 string
		arg2 *peer.SignedProposal
	}
	checkACLReturns struct {
		result1 error
	}
	checkACLReturnsOnCall map[int]struct {
		result1 error
	}
	EndorseWithPluginStub        func(string, string, []byte, *peer.SignedProposal) (*peer.Endorsement, []byte, error)
	endorseWithPluginMutex       sync.RWMutex
	endorseWithPluginArgsForCall []struct {
		arg1 string
		arg2 string
		arg3 []byte
		arg4 *peer.SignedProposal
	}
	endorseWithPluginReturns struct {
		result1 *peer.Endorsement
		result2 []byte
		result3 error
	}
	endorseWithPluginReturnsOnCall map[int]struct {
		result1 *peer.Endorsement
		result2 []byte
		result3 error
	}
	ExecuteStub        func(*ccprovider.TransactionParams, string, *peer.ChaincodeInput) (*peer.Response, *peer.ChaincodeEvent, error)
	executeMutex       sync.RWMutex
	executeArgsForCall []struct {
		arg1 *ccprovider.TransactionParams
		arg2 string
		arg3 *peer.ChaincodeInput
	}
	executeReturns struct {
		result1 *peer.Response
		result2 *peer.ChaincodeEvent
		result3 error
	}
	executeReturnsOnCall map[int]struct {
		result1 *peer.Response
		result2 *peer.ChaincodeEvent
		result3 error
	}
	ExecuteLegacyInitStub        func(*ccprovider.TransactionParams, string, string, *peer.ChaincodeInput) (*peer.Response, *peer.ChaincodeEvent, error)
	executeLegacyInitMutex       sync.RWMutex
	executeLegacyInitArgsForCall []struct {
		arg1 *ccprovider.TransactionParams
		arg2 string
		arg3 string
		arg4 *peer.ChaincodeInput
	}
	executeLegacyInitReturns struct {
		result1 *peer.Response
		result2 *peer.ChaincodeEvent
		result3 error
	}
	executeLegacyInitReturnsOnCall map[int]struct {
		result1 *peer.Response
		result2 *peer.ChaincodeEvent
		result3 error
	}
	GetDeployedCCInfoProviderStub        func() ledger.DeployedChaincodeInfoProvider
	getDeployedCCInfoProviderMutex       sync.RWMutex
	getDeployedCCInfoProviderArgsForCall []struct {
	}
	getDeployedCCInfoProviderReturns struct {
		result1 ledger.DeployedChaincodeInfoProvider
	}
	getDeployedCCInfoProviderReturnsOnCall map[int]struct {
		result1 ledger.DeployedChaincodeInfoProvider
	}
	GetHistoryQueryExecutorStub        func(string) (ledger.HistoryQueryExecutor, error)
	getHistoryQueryExecutorMutex       sync.RWMutex
	getHistoryQueryExecutorArgsForCall []struct {
		arg1 string
	}
	getHistoryQueryExecutorReturns struct {
		result1 ledger.HistoryQueryExecutor
		result2 error
	}
	getHistoryQueryExecutorReturnsOnCall map[int]struct {
		result1 ledger.HistoryQueryExecutor
		result2 error
	}
	GetLedgerHeightStub        func(string) (uint64, error)
	getLedgerHeightMutex       sync.RWMutex
	getLedgerHeightArgsForCall []struct {
		arg1 string
	}
	getLedgerHeightReturns struct {
		result1 uint64
		result2 error
	}
	getLedgerHeightReturnsOnCall map[int]struct {
		result1 uint64
		result2 error
	}
	GetTransactionByIDStub        func(string, string) (*peer.ProcessedTransaction, error)
	getTransactionByIDMutex       sync.RWMutex
	getTransactionByIDArgsForCall []struct {
		arg1 string
		arg2 string
	}
	getTransactionByIDReturns struct {
		result1 *peer.ProcessedTransaction
		result2 error
	}
	getTransactionByIDReturnsOnCall map[int]struct {
		result1 *peer.ProcessedTransaction
		result2 error
	}
	GetTxSimulatorStub        func(string, string) (ledger.TxSimulator, error)
	getTxSimulatorMutex       sync.RWMutex
	getTxSimulatorArgsForCall []struct {
		arg1 string
		arg2 string
	}
	getTxSimulatorReturns struct {
		result1 ledger.TxSimulator
		result2 error
	}
	getTxSimulatorReturnsOnCall map[int]struct {
		result1 ledger.TxSimulator
		result2 error
	}
	IsSysCCStub        func(string) bool
	isSysCCMutex       sync.RWMutex
	isSysCCArgsForCall []struct {
		arg1 string
	}
	isSysCCReturns struct {
		result1 bool
	}
	isSysCCReturnsOnCall map[int]struct {
		result1 bool
	}
	SerializeStub        func() ([]byte, error)
	serializeMutex       sync.RWMutex
	serializeArgsForCall []struct {
	}
	serializeReturns struct {
		result1 []byte
		result2 error
	}
	serializeReturnsOnCall map[int]struct {
		result1 []byte
		result2 error
	}
	SignStub        func([]byte) ([]byte, error)
	signMutex       sync.RWMutex
	signArgsForCall []struct {
		arg1 []byte
	}
	signReturns struct {
		result1 []byte
		result2 error
	}
	signReturnsOnCall map[int]struct {
		result1 []byte
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Support) ChaincodeEndorsementInfo(arg1 string, arg2 string, arg3 ledger.QueryExecutor) (*lifecycle.ChaincodeEndorsementInfo, error) {
	fake.chaincodeEndorsementInfoMutex.Lock()
	ret, specificReturn := fake.chaincodeEndorsementInfoReturnsOnCall[len(fake.chaincodeEndorsementInfoArgsForCall)]
	fake.chaincodeEndorsementInfoArgsForCall = append(fake.chaincodeEndorsementInfoArgsForCall, struct {
		arg1 string
		arg2 string
		arg3 ledger.QueryExecutor
	}{arg1, arg2, arg3})
	fake.recordInvocation("ChaincodeEndorsementInfo", []interface{}{arg1, arg2, arg3})
	fake.chaincodeEndorsementInfoMutex.Unlock()
	if fake.ChaincodeEndorsementInfoStub != nil {
		return fake.ChaincodeEndorsementInfoStub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.chaincodeEndorsementInfoReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Support) ChaincodeEndorsementInfoCallCount() int {
	fake.chaincodeEndorsementInfoMutex.RLock()
	defer fake.chaincodeEndorsementInfoMutex.RUnlock()
	return len(fake.chaincodeEndorsementInfoArgsForCall)
}

func (fake *Support) ChaincodeEndorsementInfoCalls(stub func(string, string, ledger.QueryExecutor) (*lifecycle.ChaincodeEndorsementInfo, error)) {
	fake.chaincodeEndorsementInfoMutex.Lock()
	defer fake.chaincodeEndorsementInfoMutex.Unlock()
	fake.ChaincodeEndorsementInfoStub = stub
}

func (fake *Support) ChaincodeEndorsementInfoArgsForCall(i int) (string, string, ledger.QueryExecutor) {
	fake.chaincodeEndorsementInfoMutex.RLock()
	defer fake.chaincodeEndorsementInfoMutex.RUnlock()
	argsForCall := fake.chaincodeEndorsementInfoArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *Support) ChaincodeEndorsementInfoReturns(result1 *lifecycle.ChaincodeEndorsementInfo, result2 error) {
	fake.chaincodeEndorsementInfoMutex.Lock()
	defer fake.chaincodeEndorsementInfoMutex.Unlock()
	fake.ChaincodeEndorsementInfoStub = nil
	fake.chaincodeEndorsementInfoReturns = struct {
		result1 *lifecycle.ChaincodeEndorsementInfo
		result2 error
	}{result1, result2}
}

func (fake *Support) ChaincodeEndorsementInfoReturnsOnCall(i int, result1 *lifecycle.ChaincodeEndorsementInfo, result2 error) {
	fake.chaincodeEndorsementInfoMutex.Lock()
	defer fake.chaincodeEndorsementInfoMutex.Unlock()
	fake.ChaincodeEndorsementInfoStub = nil
	if fake.chaincodeEndorsementInfoReturnsOnCall == nil {
		fake.chaincodeEndorsementInfoReturnsOnCall = make(map[int]struct {
			result1 *lifecycle.ChaincodeEndorsementInfo
			result2 error
		})
	}
	fake.chaincodeEndorsementInfoReturnsOnCall[i] = struct {
		result1 *lifecycle.ChaincodeEndorsementInfo
		result2 error
	}{result1, result2}
}

func (fake *Support) CheckACL(arg1 string, arg2 *peer.SignedProposal) error {
	fake.checkACLMutex.Lock()
	ret, specificReturn := fake.checkACLReturnsOnCall[len(fake.checkACLArgsForCall)]
	fake.checkACLArgsForCall = append(fake.checkACLArgsForCall, struct {
		arg1 string
		arg2 *peer.SignedProposal
	}{arg1, arg2})
	fake.recordInvocation("CheckACL", []interface{}{arg1, arg2})
	fake.checkACLMutex.Unlock()
	if fake.CheckACLStub != nil {
		return fake.CheckACLStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.checkACLReturns
	return fakeReturns.result1
}

func (fake *Support) CheckACLCallCount() int {
	fake.checkACLMutex.RLock()
	defer fake.checkACLMutex.RUnlock()
	return len(fake.checkACLArgsForCall)
}

func (fake *Support) CheckACLCalls(stub func(string, *peer.SignedProposal) error) {
	fake.checkACLMutex.Lock()
	defer fake.checkACLMutex.Unlock()
	fake.CheckACLStub = stub
}

func (fake *Support) CheckACLArgsForCall(i int) (string, *peer.SignedProposal) {
	fake.checkACLMutex.RLock()
	defer fake.checkACLMutex.RUnlock()
	argsForCall := fake.checkACLArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *Support) CheckACLReturns(result1 error) {
	fake.checkACLMutex.Lock()
	defer fake.checkACLMutex.Unlock()
	fake.CheckACLStub = nil
	fake.checkACLReturns = struct {
		result1 error
	}{result1}
}

func (fake *Support) CheckACLReturnsOnCall(i int, result1 error) {
	fake.checkACLMutex.Lock()
	defer fake.checkACLMutex.Unlock()
	fake.CheckACLStub = nil
	if fake.checkACLReturnsOnCall == nil {
		fake.checkACLReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.checkACLReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *Support) EndorseWithPlugin(arg1 string, arg2 string, arg3 []byte, arg4 *peer.SignedProposal) (*peer.Endorsement, []byte, error) {
	var arg3Copy []byte
	if arg3 != nil {
		arg3Copy = make([]byte, len(arg3))
		copy(arg3Copy, arg3)
	}
	fake.endorseWithPluginMutex.Lock()
	ret, specificReturn := fake.endorseWithPluginReturnsOnCall[len(fake.endorseWithPluginArgsForCall)]
	fake.endorseWithPluginArgsForCall = append(fake.endorseWithPluginArgsForCall, struct {
		arg1 string
		arg2 string
		arg3 []byte
		arg4 *peer.SignedProposal
	}{arg1, arg2, arg3Copy, arg4})
	fake.recordInvocation("EndorseWithPlugin", []interface{}{arg1, arg2, arg3Copy, arg4})
	fake.endorseWithPluginMutex.Unlock()
	if fake.EndorseWithPluginStub != nil {
		return fake.EndorseWithPluginStub(arg1, arg2, arg3, arg4)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	fakeReturns := fake.endorseWithPluginReturns
	return fakeReturns.result1, fakeReturns.result2, fakeReturns.result3
}

func (fake *Support) EndorseWithPluginCallCount() int {
	fake.endorseWithPluginMutex.RLock()
	defer fake.endorseWithPluginMutex.RUnlock()
	return len(fake.endorseWithPluginArgsForCall)
}

func (fake *Support) EndorseWithPluginCalls(stub func(string, string, []byte, *peer.SignedProposal) (*peer.Endorsement, []byte, error)) {
	fake.endorseWithPluginMutex.Lock()
	defer fake.endorseWithPluginMutex.Unlock()
	fake.EndorseWithPluginStub = stub
}

func (fake *Support) EndorseWithPluginArgsForCall(i int) (string, string, []byte, *peer.SignedProposal) {
	fake.endorseWithPluginMutex.RLock()
	defer fake.endorseWithPluginMutex.RUnlock()
	argsForCall := fake.endorseWithPluginArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4
}

func (fake *Support) EndorseWithPluginReturns(result1 *peer.Endorsement, result2 []byte, result3 error) {
	fake.endorseWithPluginMutex.Lock()
	defer fake.endorseWithPluginMutex.Unlock()
	fake.EndorseWithPluginStub = nil
	fake.endorseWithPluginReturns = struct {
		result1 *peer.Endorsement
		result2 []byte
		result3 error
	}{result1, result2, result3}
}

func (fake *Support) EndorseWithPluginReturnsOnCall(i int, result1 *peer.Endorsement, result2 []byte, result3 error) {
	fake.endorseWithPluginMutex.Lock()
	defer fake.endorseWithPluginMutex.Unlock()
	fake.EndorseWithPluginStub = nil
	if fake.endorseWithPluginReturnsOnCall == nil {
		fake.endorseWithPluginReturnsOnCall = make(map[int]struct {
			result1 *peer.Endorsement
			result2 []byte
			result3 error
		})
	}
	fake.endorseWithPluginReturnsOnCall[i] = struct {
		result1 *peer.Endorsement
		result2 []byte
		result3 error
	}{result1, result2, result3}
}

func (fake *Support) Execute(arg1 *ccprovider.TransactionParams, arg2 string, arg3 *peer.ChaincodeInput) (*peer.Response, *peer.ChaincodeEvent, error) {
	fake.executeMutex.Lock()
	ret, specificReturn := fake.executeReturnsOnCall[len(fake.executeArgsForCall)]
	fake.executeArgsForCall = append(fake.executeArgsForCall, struct {
		arg1 *ccprovider.TransactionParams
		arg2 string
		arg3 *peer.ChaincodeInput
	}{arg1, arg2, arg3})
	fake.recordInvocation("Execute", []interface{}{arg1, arg2, arg3})
	fake.executeMutex.Unlock()
	if fake.ExecuteStub != nil {
		return fake.ExecuteStub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	fakeReturns := fake.executeReturns
	return fakeReturns.result1, fakeReturns.result2, fakeReturns.result3
}

func (fake *Support) ExecuteCallCount() int {
	fake.executeMutex.RLock()
	defer fake.executeMutex.RUnlock()
	return len(fake.executeArgsForCall)
}

func (fake *Support) ExecuteCalls(stub func(*ccprovider.TransactionParams, string, *peer.ChaincodeInput) (*peer.Response, *peer.ChaincodeEvent, error)) {
	fake.executeMutex.Lock()
	defer fake.executeMutex.Unlock()
	fake.ExecuteStub = stub
}

func (fake *Support) ExecuteArgsForCall(i int) (*ccprovider.TransactionParams, string, *peer.ChaincodeInput) {
	fake.executeMutex.RLock()
	defer fake.executeMutex.RUnlock()
	argsForCall := fake.executeArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *Support) ExecuteReturns(result1 *peer.Response, result2 *peer.ChaincodeEvent, result3 error) {
	fake.executeMutex.Lock()
	defer fake.executeMutex.Unlock()
	fake.ExecuteStub = nil
	fake.executeReturns = struct {
		result1 *peer.Response
		result2 *peer.ChaincodeEvent
		result3 error
	}{result1, result2, result3}
}

func (fake *Support) ExecuteReturnsOnCall(i int, result1 *peer.Response, result2 *peer.ChaincodeEvent, result3 error) {
	fake.executeMutex.Lock()
	defer fake.executeMutex.Unlock()
	fake.ExecuteStub = nil
	if fake.executeReturnsOnCall == nil {
		fake.executeReturnsOnCall = make(map[int]struct {
			result1 *peer.Response
			result2 *peer.ChaincodeEvent
			result3 error
		})
	}
	fake.executeReturnsOnCall[i] = struct {
		result1 *peer.Response
		result2 *peer.ChaincodeEvent
		result3 error
	}{result1, result2, result3}
}

func (fake *Support) ExecuteLegacyInit(arg1 *ccprovider.TransactionParams, arg2 string, arg3 string, arg4 *peer.ChaincodeInput) (*peer.Response, *peer.ChaincodeEvent, error) {
	fake.executeLegacyInitMutex.Lock()
	ret, specificReturn := fake.executeLegacyInitReturnsOnCall[len(fake.executeLegacyInitArgsForCall)]
	fake.executeLegacyInitArgsForCall = append(fake.executeLegacyInitArgsForCall, struct {
		arg1 *ccprovider.TransactionParams
		arg2 string
		arg3 string
		arg4 *peer.ChaincodeInput
	}{arg1, arg2, arg3, arg4})
	fake.recordInvocation("ExecuteLegacyInit", []interface{}{arg1, arg2, arg3, arg4})
	fake.executeLegacyInitMutex.Unlock()
	if fake.ExecuteLegacyInitStub != nil {
		return fake.ExecuteLegacyInitStub(arg1, arg2, arg3, arg4)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	fakeReturns := fake.executeLegacyInitReturns
	return fakeReturns.result1, fakeReturns.result2, fakeReturns.result3
}

func (fake *Support) ExecuteLegacyInitCallCount() int {
	fake.executeLegacyInitMutex.RLock()
	defer fake.executeLegacyInitMutex.RUnlock()
	return len(fake.executeLegacyInitArgsForCall)
}

func (fake *Support) ExecuteLegacyInitCalls(stub func(*ccprovider.TransactionParams, string, string, *peer.ChaincodeInput) (*peer.Response, *peer.ChaincodeEvent, error)) {
	fake.executeLegacyInitMutex.Lock()
	defer fake.executeLegacyInitMutex.Unlock()
	fake.ExecuteLegacyInitStub = stub
}

func (fake *Support) ExecuteLegacyInitArgsForCall(i int) (*ccprovider.TransactionParams, string, string, *peer.ChaincodeInput) {
	fake.executeLegacyInitMutex.RLock()
	defer fake.executeLegacyInitMutex.RUnlock()
	argsForCall := fake.executeLegacyInitArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4
}

func (fake *Support) ExecuteLegacyInitReturns(result1 *peer.Response, result2 *peer.ChaincodeEvent, result3 error) {
	fake.executeLegacyInitMutex.Lock()
	defer fake.executeLegacyInitMutex.Unlock()
	fake.ExecuteLegacyInitStub = nil
	fake.executeLegacyInitReturns = struct {
		result1 *peer.Response
		result2 *peer.ChaincodeEvent
		result3 error
	}{result1, result2, result3}
}

func (fake *Support) ExecuteLegacyInitReturnsOnCall(i int, result1 *peer.Response, result2 *peer.ChaincodeEvent, result3 error) {
	fake.executeLegacyInitMutex.Lock()
	defer fake.executeLegacyInitMutex.Unlock()
	fake.ExecuteLegacyInitStub = nil
	if fake.executeLegacyInitReturnsOnCall == nil {
		fake.executeLegacyInitReturnsOnCall = make(map[int]struct {
			result1 *peer.Response
			result2 *peer.ChaincodeEvent
			result3 error
		})
	}
	fake.executeLegacyInitReturnsOnCall[i] = struct {
		result1 *peer.Response
		result2 *peer.ChaincodeEvent
		result3 error
	}{result1, result2, result3}
}

func (fake *Support) GetDeployedCCInfoProvider() ledger.DeployedChaincodeInfoProvider {
	fake.getDeployedCCInfoProviderMutex.Lock()
	ret, specificReturn := fake.getDeployedCCInfoProviderReturnsOnCall[len(fake.getDeployedCCInfoProviderArgsForCall)]
	fake.getDeployedCCInfoProviderArgsForCall = append(fake.getDeployedCCInfoProviderArgsForCall, struct {
	}{})
	fake.recordInvocation("GetDeployedCCInfoProvider", []interface{}{})
	fake.getDeployedCCInfoProviderMutex.Unlock()
	if fake.GetDeployedCCInfoProviderStub != nil {
		return fake.GetDeployedCCInfoProviderStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.getDeployedCCInfoProviderReturns
	return fakeReturns.result1
}

func (fake *Support) GetDeployedCCInfoProviderCallCount() int {
	fake.getDeployedCCInfoProviderMutex.RLock()
	defer fake.getDeployedCCInfoProviderMutex.RUnlock()
	return len(fake.getDeployedCCInfoProviderArgsForCall)
}

func (fake *Support) GetDeployedCCInfoProviderCalls(stub func() ledger.DeployedChaincodeInfoProvider) {
	fake.getDeployedCCInfoProviderMutex.Lock()
	defer fake.getDeployedCCInfoProviderMutex.Unlock()
	fake.GetDeployedCCInfoProviderStub = stub
}

func (fake *Support) GetDeployedCCInfoProviderReturns(result1 ledger.DeployedChaincodeInfoProvider) {
	fake.getDeployedCCInfoProviderMutex.Lock()
	defer fake.getDeployedCCInfoProviderMutex.Unlock()
	fake.GetDeployedCCInfoProviderStub = nil
	fake.getDeployedCCInfoProviderReturns = struct {
		result1 ledger.DeployedChaincodeInfoProvider
	}{result1}
}

func (fake *Support) GetDeployedCCInfoProviderReturnsOnCall(i int, result1 ledger.DeployedChaincodeInfoProvider) {
	fake.getDeployedCCInfoProviderMutex.Lock()
	defer fake.getDeployedCCInfoProviderMutex.Unlock()
	fake.GetDeployedCCInfoProviderStub = nil
	if fake.getDeployedCCInfoProviderReturnsOnCall == nil {
		fake.getDeployedCCInfoProviderReturnsOnCall = make(map[int]struct {
			result1 ledger.DeployedChaincodeInfoProvider
		})
	}
	fake.getDeployedCCInfoProviderReturnsOnCall[i] = struct {
		result1 ledger.DeployedChaincodeInfoProvider
	}{result1}
}

func (fake *Support) GetHistoryQueryExecutor(arg1 string) (ledger.HistoryQueryExecutor, error) {
	fake.getHistoryQueryExecutorMutex.Lock()
	ret, specificReturn := fake.getHistoryQueryExecutorReturnsOnCall[len(fake.getHistoryQueryExecutorArgsForCall)]
	fake.getHistoryQueryExecutorArgsForCall = append(fake.getHistoryQueryExecutorArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("GetHistoryQueryExecutor", []interface{}{arg1})
	fake.getHistoryQueryExecutorMutex.Unlock()
	if fake.GetHistoryQueryExecutorStub != nil {
		return fake.GetHistoryQueryExecutorStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getHistoryQueryExecutorReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Support) GetHistoryQueryExecutorCallCount() int {
	fake.getHistoryQueryExecutorMutex.RLock()
	defer fake.getHistoryQueryExecutorMutex.RUnlock()
	return len(fake.getHistoryQueryExecutorArgsForCall)
}

func (fake *Support) GetHistoryQueryExecutorCalls(stub func(string) (ledger.HistoryQueryExecutor, error)) {
	fake.getHistoryQueryExecutorMutex.Lock()
	defer fake.getHistoryQueryExecutorMutex.Unlock()
	fake.GetHistoryQueryExecutorStub = stub
}

func (fake *Support) GetHistoryQueryExecutorArgsForCall(i int) string {
	fake.getHistoryQueryExecutorMutex.RLock()
	defer fake.getHistoryQueryExecutorMutex.RUnlock()
	argsForCall := fake.getHistoryQueryExecutorArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Support) GetHistoryQueryExecutorReturns(result1 ledger.HistoryQueryExecutor, result2 error) {
	fake.getHistoryQueryExecutorMutex.Lock()
	defer fake.getHistoryQueryExecutorMutex.Unlock()
	fake.GetHistoryQueryExecutorStub = nil
	fake.getHistoryQueryExecutorReturns = struct {
		result1 ledger.HistoryQueryExecutor
		result2 error
	}{result1, result2}
}

func (fake *Support) GetHistoryQueryExecutorReturnsOnCall(i int, result1 ledger.HistoryQueryExecutor, result2 error) {
	fake.getHistoryQueryExecutorMutex.Lock()
	defer fake.getHistoryQueryExecutorMutex.Unlock()
	fake.GetHistoryQueryExecutorStub = nil
	if fake.getHistoryQueryExecutorReturnsOnCall == nil {
		fake.getHistoryQueryExecutorReturnsOnCall = make(map[int]struct {
			result1 ledger.HistoryQueryExecutor
			result2 error
		})
	}
	fake.getHistoryQueryExecutorReturnsOnCall[i] = struct {
		result1 ledger.HistoryQueryExecutor
		result2 error
	}{result1, result2}
}

func (fake *Support) GetLedgerHeight(arg1 string) (uint64, error) {
	fake.getLedgerHeightMutex.Lock()
	ret, specificReturn := fake.getLedgerHeightReturnsOnCall[len(fake.getLedgerHeightArgsForCall)]
	fake.getLedgerHeightArgsForCall = append(fake.getLedgerHeightArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("GetLedgerHeight", []interface{}{arg1})
	fake.getLedgerHeightMutex.Unlock()
	if fake.GetLedgerHeightStub != nil {
		return fake.GetLedgerHeightStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getLedgerHeightReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Support) GetLedgerHeightCallCount() int {
	fake.getLedgerHeightMutex.RLock()
	defer fake.getLedgerHeightMutex.RUnlock()
	return len(fake.getLedgerHeightArgsForCall)
}

func (fake *Support) GetLedgerHeightCalls(stub func(string) (uint64, error)) {
	fake.getLedgerHeightMutex.Lock()
	defer fake.getLedgerHeightMutex.Unlock()
	fake.GetLedgerHeightStub = stub
}

func (fake *Support) GetLedgerHeightArgsForCall(i int) string {
	fake.getLedgerHeightMutex.RLock()
	defer fake.getLedgerHeightMutex.RUnlock()
	argsForCall := fake.getLedgerHeightArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Support) GetLedgerHeightReturns(result1 uint64, result2 error) {
	fake.getLedgerHeightMutex.Lock()
	defer fake.getLedgerHeightMutex.Unlock()
	fake.GetLedgerHeightStub = nil
	fake.getLedgerHeightReturns = struct {
		result1 uint64
		result2 error
	}{result1, result2}
}

func (fake *Support) GetLedgerHeightReturnsOnCall(i int, result1 uint64, result2 error) {
	fake.getLedgerHeightMutex.Lock()
	defer fake.getLedgerHeightMutex.Unlock()
	fake.GetLedgerHeightStub = nil
	if fake.getLedgerHeightReturnsOnCall == nil {
		fake.getLedgerHeightReturnsOnCall = make(map[int]struct {
			result1 uint64
			result2 error
		})
	}
	fake.getLedgerHeightReturnsOnCall[i] = struct {
		result1 uint64
		result2 error
	}{result1, result2}
}

func (fake *Support) GetTransactionByID(arg1 string, arg2 string) (*peer.ProcessedTransaction, error) {
	fake.getTransactionByIDMutex.Lock()
	ret, specificReturn := fake.getTransactionByIDReturnsOnCall[len(fake.getTransactionByIDArgsForCall)]
	fake.getTransactionByIDArgsForCall = append(fake.getTransactionByIDArgsForCall, struct {
		arg1 string
		arg2 string
	}{arg1, arg2})
	fake.recordInvocation("GetTransactionByID", []interface{}{arg1, arg2})
	fake.getTransactionByIDMutex.Unlock()
	if fake.GetTransactionByIDStub != nil {
		return fake.GetTransactionByIDStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getTransactionByIDReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Support) GetTransactionByIDCallCount() int {
	fake.getTransactionByIDMutex.RLock()
	defer fake.getTransactionByIDMutex.RUnlock()
	return len(fake.getTransactionByIDArgsForCall)
}

func (fake *Support) GetTransactionByIDCalls(stub func(string, string) (*peer.ProcessedTransaction, error)) {
	fake.getTransactionByIDMutex.Lock()
	defer fake.getTransactionByIDMutex.Unlock()
	fake.GetTransactionByIDStub = stub
}

func (fake *Support) GetTransactionByIDArgsForCall(i int) (string, string) {
	fake.getTransactionByIDMutex.RLock()
	defer fake.getTransactionByIDMutex.RUnlock()
	argsForCall := fake.getTransactionByIDArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *Support) GetTransactionByIDReturns(result1 *peer.ProcessedTransaction, result2 error) {
	fake.getTransactionByIDMutex.Lock()
	defer fake.getTransactionByIDMutex.Unlock()
	fake.GetTransactionByIDStub = nil
	fake.getTransactionByIDReturns = struct {
		result1 *peer.ProcessedTransaction
		result2 error
	}{result1, result2}
}

func (fake *Support) GetTransactionByIDReturnsOnCall(i int, result1 *peer.ProcessedTransaction, result2 error) {
	fake.getTransactionByIDMutex.Lock()
	defer fake.getTransactionByIDMutex.Unlock()
	fake.GetTransactionByIDStub = nil
	if fake.getTransactionByIDReturnsOnCall == nil {
		fake.getTransactionByIDReturnsOnCall = make(map[int]struct {
			result1 *peer.ProcessedTransaction
			result2 error
		})
	}
	fake.getTransactionByIDReturnsOnCall[i] = struct {
		result1 *peer.ProcessedTransaction
		result2 error
	}{result1, result2}
}

func (fake *Support) GetTxSimulator(arg1 string, arg2 string) (ledger.TxSimulator, error) {
	fake.getTxSimulatorMutex.Lock()
	ret, specificReturn := fake.getTxSimulatorReturnsOnCall[len(fake.getTxSimulatorArgsForCall)]
	fake.getTxSimulatorArgsForCall = append(fake.getTxSimulatorArgsForCall, struct {
		arg1 string
		arg2 string
	}{arg1, arg2})
	fake.recordInvocation("GetTxSimulator", []interface{}{arg1, arg2})
	fake.getTxSimulatorMutex.Unlock()
	if fake.GetTxSimulatorStub != nil {
		return fake.GetTxSimulatorStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getTxSimulatorReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Support) GetTxSimulatorCallCount() int {
	fake.getTxSimulatorMutex.RLock()
	defer fake.getTxSimulatorMutex.RUnlock()
	return len(fake.getTxSimulatorArgsForCall)
}

func (fake *Support) GetTxSimulatorCalls(stub func(string, string) (ledger.TxSimulator, error)) {
	fake.getTxSimulatorMutex.Lock()
	defer fake.getTxSimulatorMutex.Unlock()
	fake.GetTxSimulatorStub = stub
}

func (fake *Support) GetTxSimulatorArgsForCall(i int) (string, string) {
	fake.getTxSimulatorMutex.RLock()
	defer fake.getTxSimulatorMutex.RUnlock()
	argsForCall := fake.getTxSimulatorArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *Support) GetTxSimulatorReturns(result1 ledger.TxSimulator, result2 error) {
	fake.getTxSimulatorMutex.Lock()
	defer fake.getTxSimulatorMutex.Unlock()
	fake.GetTxSimulatorStub = nil
	fake.getTxSimulatorReturns = struct {
		result1 ledger.TxSimulator
		result2 error
	}{result1, result2}
}

func (fake *Support) GetTxSimulatorReturnsOnCall(i int, result1 ledger.TxSimulator, result2 error) {
	fake.getTxSimulatorMutex.Lock()
	defer fake.getTxSimulatorMutex.Unlock()
	fake.GetTxSimulatorStub = nil
	if fake.getTxSimulatorReturnsOnCall == nil {
		fake.getTxSimulatorReturnsOnCall = make(map[int]struct {
			result1 ledger.TxSimulator
			result2 error
		})
	}
	fake.getTxSimulatorReturnsOnCall[i] = struct {
		result1 ledger.TxSimulator
		result2 error
	}{result1, result2}
}

func (fake *Support) IsSysCC(arg1 string) bool {
	fake.isSysCCMutex.Lock()
	ret, specificReturn := fake.isSysCCReturnsOnCall[len(fake.isSysCCArgsForCall)]
	fake.isSysCCArgsForCall = append(fake.isSysCCArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("IsSysCC", []interface{}{arg1})
	fake.isSysCCMutex.Unlock()
	if fake.IsSysCCStub != nil {
		return fake.IsSysCCStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.isSysCCReturns
	return fakeReturns.result1
}

func (fake *Support) IsSysCCCallCount() int {
	fake.isSysCCMutex.RLock()
	defer fake.isSysCCMutex.RUnlock()
	return len(fake.isSysCCArgsForCall)
}

func (fake *Support) IsSysCCCalls(stub func(string) bool) {
	fake.isSysCCMutex.Lock()
	defer fake.isSysCCMutex.Unlock()
	fake.IsSysCCStub = stub
}

func (fake *Support) IsSysCCArgsForCall(i int) string {
	fake.isSysCCMutex.RLock()
	defer fake.isSysCCMutex.RUnlock()
	argsForCall := fake.isSysCCArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Support) IsSysCCReturns(result1 bool) {
	fake.isSysCCMutex.Lock()
	defer fake.isSysCCMutex.Unlock()
	fake.IsSysCCStub = nil
	fake.isSysCCReturns = struct {
		result1 bool
	}{result1}
}

func (fake *Support) IsSysCCReturnsOnCall(i int, result1 bool) {
	fake.isSysCCMutex.Lock()
	defer fake.isSysCCMutex.Unlock()
	fake.IsSysCCStub = nil
	if fake.isSysCCReturnsOnCall == nil {
		fake.isSysCCReturnsOnCall = make(map[int]struct {
			result1 bool
		})
	}
	fake.isSysCCReturnsOnCall[i] = struct {
		result1 bool
	}{result1}
}

func (fake *Support) Serialize() ([]byte, error) {
	fake.serializeMutex.Lock()
	ret, specificReturn := fake.serializeReturnsOnCall[len(fake.serializeArgsForCall)]
	fake.serializeArgsForCall = append(fake.serializeArgsForCall, struct {
	}{})
	fake.recordInvocation("Serialize", []interface{}{})
	fake.serializeMutex.Unlock()
	if fake.SerializeStub != nil {
		return fake.SerializeStub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.serializeReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Support) SerializeCallCount() int {
	fake.serializeMutex.RLock()
	defer fake.serializeMutex.RUnlock()
	return len(fake.serializeArgsForCall)
}

func (fake *Support) SerializeCalls(stub func() ([]byte, error)) {
	fake.serializeMutex.Lock()
	defer fake.serializeMutex.Unlock()
	fake.SerializeStub = stub
}

func (fake *Support) SerializeReturns(result1 []byte, result2 error) {
	fake.serializeMutex.Lock()
	defer fake.serializeMutex.Unlock()
	fake.SerializeStub = nil
	fake.serializeReturns = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *Support) SerializeReturnsOnCall(i int, result1 []byte, result2 error) {
	fake.serializeMutex.Lock()
	defer fake.serializeMutex.Unlock()
	fake.SerializeStub = nil
	if fake.serializeReturnsOnCall == nil {
		fake.serializeReturnsOnCall = make(map[int]struct {
			result1 []byte
			result2 error
		})
	}
	fake.serializeReturnsOnCall[i] = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *Support) Sign(arg1 []byte) ([]byte, error) {
	var arg1Copy []byte
	if arg1 != nil {
		arg1Copy = make([]byte, len(arg1))
		copy(arg1Copy, arg1)
	}
	fake.signMutex.Lock()
	ret, specificReturn := fake.signReturnsOnCall[len(fake.signArgsForCall)]
	fake.signArgsForCall = append(fake.signArgsForCall, struct {
		arg1 []byte
	}{arg1Copy})
	fake.recordInvocation("Sign", []interface{}{arg1Copy})
	fake.signMutex.Unlock()
	if fake.SignStub != nil {
		return fake.SignStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.signReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Support) SignCallCount() int {
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	return len(fake.signArgsForCall)
}

func (fake *Support) SignCalls(stub func([]byte) ([]byte, error)) {
	fake.signMutex.Lock()
	defer fake.signMutex.Unlock()
	fake.SignStub = stub
}

func (fake *Support) SignArgsForCall(i int) []byte {
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	argsForCall := fake.signArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Support) SignReturns(result1 []byte, result2 error) {
	fake.signMutex.Lock()
	defer fake.signMutex.Unlock()
	fake.SignStub = nil
	fake.signReturns = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *Support) SignReturnsOnCall(i int, result1 []byte, result2 error) {
	fake.signMutex.Lock()
	defer fake.signMutex.Unlock()
	fake.SignStub = nil
	if fake.signReturnsOnCall == nil {
		fake.signReturnsOnCall = make(map[int]struct {
			result1 []byte
			result2 error
		})
	}
	fake.signReturnsOnCall[i] = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *Support) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.chaincodeEndorsementInfoMutex.RLock()
	defer fake.chaincodeEndorsementInfoMutex.RUnlock()
	fake.checkACLMutex.RLock()
	defer fake.checkACLMutex.RUnlock()
	fake.endorseWithPluginMutex.RLock()
	defer fake.endorseWithPluginMutex.RUnlock()
	fake.executeMutex.RLock()
	defer fake.executeMutex.RUnlock()
	fake.executeLegacyInitMutex.RLock()
	defer fake.executeLegacyInitMutex.RUnlock()
	fake.getDeployedCCInfoProviderMutex.RLock()
	defer fake.getDeployedCCInfoProviderMutex.RUnlock()
	fake.getHistoryQueryExecutorMutex.RLock()
	defer fake.getHistoryQueryExecutorMutex.RUnlock()
	fake.getLedgerHeightMutex.RLock()
	defer fake.getLedgerHeightMutex.RUnlock()
	fake.getTransactionByIDMutex.RLock()
	defer fake.getTransactionByIDMutex.RUnlock()
	fake.getTxSimulatorMutex.RLock()
	defer fake.getTxSimulatorMutex.RUnlock()
	fake.isSysCCMutex.RLock()
	defer fake.isSysCCMutex.RUnlock()
	fake.serializeMutex.RLock()
	defer fake.serializeMutex.RUnlock()
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Support) recordInvocation(key string, args []interface{}) {
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

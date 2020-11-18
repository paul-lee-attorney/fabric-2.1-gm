// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import common "github.com/paul-lee-attorney/fabric-2.1-gm/gossip/privdata/common"
import mock "github.com/stretchr/testify/mock"

// ReconciliationFetcher is an autogenerated mock type for the ReconciliationFetcher type
type ReconciliationFetcher struct {
	mock.Mock
}

// FetchReconciledItems provides a mock function with given fields: dig2collectionConfig
func (_m *ReconciliationFetcher) FetchReconciledItems(dig2collectionConfig common.Dig2CollectionConfig) (*common.FetchedPvtDataContainer, error) {
	ret := _m.Called(dig2collectionConfig)

	var r0 *common.FetchedPvtDataContainer
	if rf, ok := ret.Get(0).(func(common.Dig2CollectionConfig) *common.FetchedPvtDataContainer); ok {
		r0 = rf(dig2collectionConfig)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*common.FetchedPvtDataContainer)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(common.Dig2CollectionConfig) error); ok {
		r1 = rf(dig2collectionConfig)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

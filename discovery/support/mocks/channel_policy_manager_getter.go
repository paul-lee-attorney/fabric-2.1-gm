// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"
import policies "github.com/paul-lee-attorney/fabric-2.1-gm/common/policies"

// ChannelPolicyManagerGetter is an autogenerated mock type for the ChannelPolicyManagerGetter type
type ChannelPolicyManagerGetter struct {
	mock.Mock
}

// Manager provides a mock function with given fields: channelID
func (_m *ChannelPolicyManagerGetter) Manager(channelID string) policies.Manager {
	ret := _m.Called(channelID)

	var r0 policies.Manager
	if rf, ok := ret.Get(0).(func(string) policies.Manager); ok {
		r0 = rf(channelID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(policies.Manager)
		}
	}

	return r0
}

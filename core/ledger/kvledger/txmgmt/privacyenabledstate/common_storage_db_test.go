/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package privacyenabledstate_test

import (
	"testing"

	. "github.com/onsi/gomega"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger/kvledger/txmgmt/privacyenabledstate"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger/kvledger/txmgmt/statedb/statecouchdb"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger/kvledger/txmgmt/statedb/stateleveldb"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger/mock"
)

func TestHealthCheckRegister(t *testing.T) {
	gt := NewGomegaWithT(t)
	fakeHealthCheckRegistry := &mock.HealthCheckRegistry{}

	dbProvider := &privacyenabledstate.CommonStorageDBProvider{
		VersionedDBProvider: &stateleveldb.VersionedDBProvider{},
		HealthCheckRegistry: fakeHealthCheckRegistry,
	}

	err := dbProvider.RegisterHealthChecker()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(fakeHealthCheckRegistry.RegisterCheckerCallCount()).To(Equal(0))

	dbProvider.VersionedDBProvider = &statecouchdb.VersionedDBProvider{}
	err = dbProvider.RegisterHealthChecker()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(fakeHealthCheckRegistry.RegisterCheckerCallCount()).To(Equal(1))

	arg1, arg2 := fakeHealthCheckRegistry.RegisterCheckerArgsForCall(0)
	gt.Expect(arg1).To(Equal("couchdb"))
	gt.Expect(arg2).NotTo(Equal(nil))
}

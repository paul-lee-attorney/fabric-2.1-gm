/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package privacyenabledstate

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/paul-lee-attorney/fabric-2.1-gm/common/metrics/disabled"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger/kvledger/bookkeeping"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger/kvledger/txmgmt/statedb/statecouchdb"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger/mock"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger/util/couchdb"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger/util/couchdbtest"
	"github.com/stretchr/testify/assert"
)

// TestEnv - an interface that a test environment implements
type TestEnv interface {
	StartExternalResource()
	Init(t testing.TB)
	GetDBHandle(id string) DB
	GetName() string
	Cleanup()
	StopExternalResource()
}

// Tests will be run against each environment in this array
// For example, to skip CouchDB tests, remove &couchDBLockBasedEnv{}
//var testEnvs = []testEnv{&levelDBCommonStorageTestEnv{}, &couchDBCommonStorageTestEnv{}}
var testEnvs = []TestEnv{&LevelDBCommonStorageTestEnv{}, &CouchDBCommonStorageTestEnv{}}

///////////// LevelDB Environment //////////////

// LevelDBCommonStorageTestEnv implements TestEnv interface for leveldb based storage
type LevelDBCommonStorageTestEnv struct {
	t                 testing.TB
	provider          DBProvider
	bookkeeperTestEnv *bookkeeping.TestEnv
	dbPath            string
}

// Init implements corresponding function from interface TestEnv
func (env *LevelDBCommonStorageTestEnv) Init(t testing.TB) {
	dbPath, err := ioutil.TempDir("", "cstestenv")
	if err != nil {
		t.Fatalf("Failed to create level db storage directory: %s", err)
	}
	env.bookkeeperTestEnv = bookkeeping.NewTestEnv(t)
	dbProvider, err := NewCommonStorageDBProvider(
		env.bookkeeperTestEnv.TestProvider,
		&disabled.Provider{},
		&mock.HealthCheckRegistry{},
		&StateDBConfig{
			&ledger.StateDBConfig{},
			dbPath,
		},
		[]string{"lscc", "_lifecycle"},
	)
	assert.NoError(t, err)
	env.t = t
	env.provider = dbProvider
	env.dbPath = dbPath
}

// StartExternalResource will be an empty implementation for levelDB test environment.
func (env *LevelDBCommonStorageTestEnv) StartExternalResource() {
	// empty implementation
}

// StopExternalResource will be an empty implementation for levelDB test environment.
func (env *LevelDBCommonStorageTestEnv) StopExternalResource() {
	// empty implementation
}

// GetDBHandle implements corresponding function from interface TestEnv
func (env *LevelDBCommonStorageTestEnv) GetDBHandle(id string) DB {
	db, err := env.provider.GetDBHandle(id)
	assert.NoError(env.t, err)
	return db
}

// GetName implements corresponding function from interface TestEnv
func (env *LevelDBCommonStorageTestEnv) GetName() string {
	return "levelDBCommonStorageTestEnv"
}

// Cleanup implements corresponding function from interface TestEnv
func (env *LevelDBCommonStorageTestEnv) Cleanup() {
	env.provider.Close()
	env.bookkeeperTestEnv.Cleanup()
	os.RemoveAll(env.dbPath)
}

///////////// CouchDB Environment //////////////

// CouchDBCommonStorageTestEnv implements TestEnv interface for couchdb based storage
type CouchDBCommonStorageTestEnv struct {
	couchAddress      string
	t                 testing.TB
	provider          DBProvider
	bookkeeperTestEnv *bookkeeping.TestEnv
	redoPath          string
	couchCleanup      func()
}

// StartExternalResource starts external couchDB resources.
func (env *CouchDBCommonStorageTestEnv) StartExternalResource() {
	if env.couchAddress == "" {
		env.couchAddress, env.couchCleanup = couchdbtest.CouchDBSetup(nil)
	}
}

// StopExternalResource stops external couchDB resources.
func (env *CouchDBCommonStorageTestEnv) StopExternalResource() {
	if env.couchAddress != "" {
		env.couchCleanup()
	}
}

// Init implements corresponding function from interface TestEnv
func (env *CouchDBCommonStorageTestEnv) Init(t testing.TB) {
	redoPath, err := ioutil.TempDir("", "pestate")
	if err != nil {
		t.Fatalf("Failed to create redo log directory: %s", err)
	}

	env.StartExternalResource()

	stateDBConfig := &StateDBConfig{
		StateDBConfig: &ledger.StateDBConfig{
			StateDatabase: "CouchDB",
			CouchDB: &couchdb.Config{
				Address:             env.couchAddress,
				Username:            "",
				Password:            "",
				MaxRetries:          3,
				MaxRetriesOnStartup: 20,
				RequestTimeout:      35 * time.Second,
				InternalQueryLimit:  1000,
				MaxBatchUpdateSize:  1000,
				RedoLogPath:         redoPath,
			},
		},
		LevelDBPath: "",
	}

	env.bookkeeperTestEnv = bookkeeping.NewTestEnv(t)
	dbProvider, err := NewCommonStorageDBProvider(
		env.bookkeeperTestEnv.TestProvider,
		&disabled.Provider{},
		&mock.HealthCheckRegistry{},
		stateDBConfig,
		[]string{"lscc", "_lifecycle"},
	)
	assert.NoError(t, err)
	env.t = t
	env.provider = dbProvider
	env.redoPath = redoPath
}

// GetDBHandle implements corresponding function from interface TestEnv
func (env *CouchDBCommonStorageTestEnv) GetDBHandle(id string) DB {
	db, err := env.provider.GetDBHandle(id)
	assert.NoError(env.t, err)
	return db
}

// GetName implements corresponding function from interface TestEnv
func (env *CouchDBCommonStorageTestEnv) GetName() string {
	return "couchDBCommonStorageTestEnv"
}

// Cleanup implements corresponding function from interface TestEnv
func (env *CouchDBCommonStorageTestEnv) Cleanup() {
	csdbProvider := env.provider.(*CommonStorageDBProvider)
	if csdbProvider != nil {
		statecouchdb.CleanupDB(env.t, csdbProvider.VersionedDBProvider)
	}
	os.RemoveAll(env.redoPath)
	env.bookkeeperTestEnv.Cleanup()
	env.provider.Close()
}

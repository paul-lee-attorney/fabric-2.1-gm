/*
Copyright Paul Lee based on IBM's works. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/stretchr/testify/assert"
)

func TestInvalidStore(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryKeyStore()

	err := ks.StoreKey(nil)
	assert.EqualError(t, err, "key is nil")
}

func TestInvalidLoad(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryKeyStore()

	_, err := ks.GetKey(nil)
	assert.EqualError(t, err, "ski is nil or empty")
}

func TestNoKeyFound(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryKeyStore()

	ski := []byte("foo")
	_, err := ks.GetKey(ski)
	assert.EqualError(t, err, fmt.Sprintf("no key found for ski %x", ski))
}

func TestStoreLoad(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryKeyStore()

	// generate a key for the keystore to find
	privKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	cspKey := &sm2PrivateKey{privKey}

	// store key
	err = ks.StoreKey(cspKey)
	assert.NoError(t, err)

	// load key
	key, err := ks.GetKey(cspKey.SKI())
	assert.NoError(t, err)

	assert.Equal(t, cspKey, key)
}

func TestReadOnly(t *testing.T) {
	t.Parallel()
	ks := NewInMemoryKeyStore()
	readonly := ks.ReadOnly()
	assert.Equal(t, false, readonly)
}

func TestStoreExisting(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryKeyStore()

	// generate a key for the keystore to find
	privKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	cspKey := &sm2PrivateKey{privKey}

	// store key
	err = ks.StoreKey(cspKey)
	assert.NoError(t, err)

	// store key a second time
	err = ks.StoreKey(cspKey)
	assert.EqualError(t, err, fmt.Sprintf("ski %x already exists in the keystore", cspKey.SKI()))
}

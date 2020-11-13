/*
Copyright Paul Lee based on IBM's works. 2020 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"errors"
	"reflect"
	"testing"

	mocks2 "github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/mocks"
	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/sw/mocks"
	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/stretchr/testify/assert"
)

func TestKeyGen(t *testing.T) {
	t.Parallel()

	expectedOpts := &mocks2.KeyGenOpts{EphemeralValue: true}
	expectetValue := &mocks2.MockKey{}
	expectedErr := errors.New("Expected Error")

	keyGenerators := make(map[reflect.Type]KeyGenerator)
	keyGenerators[reflect.TypeOf(&mocks2.KeyGenOpts{})] = &mocks.KeyGenerator{
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     expectedErr,
	}
	csp := CSP{KeyGenerators: keyGenerators}
	value, err := csp.KeyGen(expectedOpts)
	assert.Nil(t, value)
	assert.Contains(t, err.Error(), expectedErr.Error())

	keyGenerators = make(map[reflect.Type]KeyGenerator)
	keyGenerators[reflect.TypeOf(&mocks2.KeyGenOpts{})] = &mocks.KeyGenerator{
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     nil,
	}
	csp = CSP{KeyGenerators: keyGenerators}
	value, err = csp.KeyGen(expectedOpts)
	assert.Equal(t, expectetValue, value)
	assert.Nil(t, err)
}

func TestSM2KeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &sm2KeyGenerator{curve: sm2.GetSM2P256V1()}

	k, err := kg.KeyGen(nil)
	assert.NoError(t, err)

	sm2K, ok := k.(*sm2PrivateKey)
	assert.True(t, ok)
	assert.NotNil(t, sm2K.privKey)
	assert.Equal(t, sm2K.privKey.Curve, sm2.GetSM2P256V1())
}

func TestSM4KeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &sm4KeyGenerator{length: 16}

	k, err := kg.KeyGen(nil)
	assert.NoError(t, err)

	sm4K, ok := k.(*sm4PrivateKey)
	assert.True(t, ok)
	assert.NotNil(t, sm4K.privKey)
	assert.Equal(t, len(sm4K.privKey), 16)
}

func TestSM4KeyGeneratorInvalidInputs(t *testing.T) {
	t.Parallel()

	kg := &sm4KeyGenerator{length: -1}

	_, err := kg.KeyGen(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Len must be larger than 0")
}

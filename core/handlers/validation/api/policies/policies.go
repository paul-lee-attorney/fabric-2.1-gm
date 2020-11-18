/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validation

import (
	validation "github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/validation/api"
	"github.com/paul-lee-attorney/fabric-2.1-gm/protoutil"
)

// PolicyEvaluator evaluates policies
type PolicyEvaluator interface {
	validation.Dependency

	// Evaluate takes a set of SignedData and evaluates whether this set of signatures satisfies
	// the policy with the given bytes
	Evaluate(policyBytes []byte, signatureSet []*protoutil.SignedData) error
}

// SerializedPolicy defines a serialized policy
type SerializedPolicy interface {
	validation.ContextDatum

	// Bytes returns the bytes of the SerializedPolicy
	Bytes() []byte
}

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aclmgmt

import (
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/flogging"
)

var aclLogger = flogging.MustGetLogger("aclmgmt")

type ACLProvider interface {
	//CheckACL checks the ACL for the resource for the channel using the
	//idinfo. idinfo is an object such as SignedProposal from which an
	//id can be extracted for testing against a policy
	CheckACL(resName string, channelID string, idinfo interface{}) error
}

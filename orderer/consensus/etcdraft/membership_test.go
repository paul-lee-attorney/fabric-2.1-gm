/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package etcdraft_test

import (
	"fmt"
	"testing"

	etcdraftproto "github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/channelconfig"
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/crypto/tlsgen"
	"github.com/paul-lee-attorney/fabric-2.1-gm/orderer/consensus/etcdraft"
	"github.com/paul-lee-attorney/fabric-2.1-gm/orderer/consensus/etcdraft/mocks"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/raft/raftpb"
)

func TestQuorumCheck(t *testing.T) {
	tests := []struct {
		Name          string
		NewConsenters map[uint64]*etcdraftproto.Consenter
		ConfChange    *raftpb.ConfChange
		RotateNode    uint64
		ActiveNodes   []uint64
		QuorumLoss    bool
	}{
		// Notations:
		//  1     - node 1 is alive
		// (1)    - node 1 is dead
		//  1'    - node 1's cert is being rotated. Node is considered to be dead in new set

		// Add
		{
			Name:          "[1]->[1,(2)]",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil, 2: nil},
			ConfChange:    &raftpb.ConfChange{NodeID: 2, Type: raftpb.ConfChangeAddNode},
			ActiveNodes:   []uint64{1},
			QuorumLoss:    false,
		},
		{
			Name:          "[1,2]->[1,2,(3)]",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil, 2: nil, 3: nil},
			ConfChange:    &raftpb.ConfChange{NodeID: 3, Type: raftpb.ConfChangeAddNode},
			ActiveNodes:   []uint64{1, 2},
			QuorumLoss:    false,
		},
		{
			Name:          "[1,2,(3)]->[1,2,(3),(4)]",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil, 2: nil, 3: nil, 4: nil},
			ConfChange:    &raftpb.ConfChange{NodeID: 4, Type: raftpb.ConfChangeAddNode},
			ActiveNodes:   []uint64{1, 2},
			QuorumLoss:    true,
		},
		{
			Name:          "[1,2,3,(4)]->[1,2,3,(4),(5)]",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil, 2: nil, 3: nil, 4: nil, 5: nil},
			ConfChange:    &raftpb.ConfChange{NodeID: 5, Type: raftpb.ConfChangeAddNode},
			ActiveNodes:   []uint64{1, 2, 3},
			QuorumLoss:    false,
		},
		// Rotate
		{
			Name:          "[1]->[1']",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil},
			RotateNode:    1,
			ActiveNodes:   []uint64{1},
			QuorumLoss:    false,
		},
		{
			Name:          "[1,2]->[1,2']",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil, 2: nil},
			RotateNode:    2,
			ActiveNodes:   []uint64{1, 2},
			QuorumLoss:    false,
		},
		{
			Name:          "[1,2,(3)]->[1,2',(3)]",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil, 2: nil, 3: nil},
			RotateNode:    2,
			ActiveNodes:   []uint64{1, 2},
			QuorumLoss:    true,
		},
		{
			Name:          "[1,2,(3)]->[1,2,(3')]",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil, 2: nil, 3: nil},
			RotateNode:    3,
			ActiveNodes:   []uint64{1, 2},
			QuorumLoss:    false,
		},
		// Remove
		{
			Name:          "[1,2,(3)]->[1,2]",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil, 2: nil},
			ConfChange:    &raftpb.ConfChange{NodeID: 3, Type: raftpb.ConfChangeRemoveNode},
			ActiveNodes:   []uint64{1, 2},
			QuorumLoss:    false,
		},
		{
			Name:          "[1,2,(3)]->[1,(3)]",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil, 3: nil},
			ConfChange:    &raftpb.ConfChange{NodeID: 2, Type: raftpb.ConfChangeRemoveNode},
			ActiveNodes:   []uint64{1, 2},
			QuorumLoss:    true,
		},
		{
			Name:          "[1,2]->[1]",
			NewConsenters: map[uint64]*etcdraftproto.Consenter{1: nil},
			ConfChange:    &raftpb.ConfChange{NodeID: 2, Type: raftpb.ConfChangeRemoveNode},
			ActiveNodes:   []uint64{1, 2},
			QuorumLoss:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			changes := &etcdraft.MembershipChanges{
				NewConsenters: test.NewConsenters,
				ConfChange:    test.ConfChange,
				RotatedNode:   test.RotateNode,
			}

			require.Equal(t, test.QuorumLoss, changes.UnacceptableQuorumLoss(test.ActiveNodes))
		})
	}
}

func TestMembershipChanges(t *testing.T) {
	blockMetadata := &etcdraftproto.BlockMetadata{
		ConsenterIds:    []uint64{1, 2},
		NextConsenterId: 3,
	}

	// generate certs for adding a new consenter
	// certs for fake-org
	tlsCA, err := tlsgen.NewCA()
	require.NoError(t, err)
	client1, err := tlsCA.NewClientCertKeyPair()
	require.NoError(t, err)
	tlsIntermediateCA, err := tlsCA.NewIntermediateCA()
	require.NoError(t, err)
	client2, err := tlsIntermediateCA.NewClientCertKeyPair()
	require.NoError(t, err)

	// certs for fake-org2
	tlsCA2, err := tlsgen.NewCA()
	require.NoError(t, err)
	client3, err := tlsCA2.NewClientCertKeyPair()
	require.NoError(t, err)
	tlsIntermediateCA2, err := tlsCA2.NewIntermediateCA()
	require.NoError(t, err)
	client4, err := tlsIntermediateCA2.NewClientCertKeyPair()
	require.NoError(t, err)

	// cert for fake-org3
	tlsCA3, err := tlsgen.NewCA()
	require.NoError(t, err)
	client5, err := tlsCA3.NewClientCertKeyPair()
	require.NoError(t, err)

	c := []*etcdraftproto.Consenter{
		{ClientTlsCert: client1.Cert, ServerTlsCert: client1.Cert},
		{ClientTlsCert: client2.Cert, ServerTlsCert: client2.Cert},
		{ClientTlsCert: client3.Cert, ServerTlsCert: client3.Cert},
		{ClientTlsCert: client4.Cert, ServerTlsCert: client4.Cert},
	}

	mockOrdererConfig := &mocks.OrdererConfig{}
	mockOrg := &mocks.OrdererOrg{}
	mockMSP := &mocks.MSP{}
	mockMSP.GetTLSRootCertsReturns([][]byte{
		tlsCA.CertBytes(),
	})
	mockMSP.GetTLSIntermediateCertsReturns([][]byte{
		tlsIntermediateCA.CertBytes(),
	})
	mockOrg.MSPReturns(mockMSP)

	mockOrg2 := &mocks.OrdererOrg{}
	mockMSP2 := &mocks.MSP{}
	mockMSP2.GetTLSRootCertsReturns([][]byte{
		tlsCA2.CertBytes(),
	})
	mockMSP2.GetTLSIntermediateCertsReturns([][]byte{
		tlsIntermediateCA2.CertBytes(),
	})

	mockOrg2.MSPReturns(mockMSP2)

	mockOrdererConfig.OrganizationsReturns(map[string]channelconfig.OrdererOrg{
		"fake-org":  mockOrg,
		"fake-org2": mockOrg2,
	})

	tests := []struct {
		Name             string
		OldConsenters    map[uint64]*etcdraftproto.Consenter
		NewConsenters    []*etcdraftproto.Consenter
		Changes          *etcdraft.MembershipChanges
		Changed, Rotated bool
		ExpectedErr      string
	}{
		{
			Name: "Add a node",
			OldConsenters: map[uint64]*etcdraftproto.Consenter{
				1: c[0],
				2: c[1],
			},
			NewConsenters: []*etcdraftproto.Consenter{
				c[0],
				c[1],
				c[2],
			},
			Changes: &etcdraft.MembershipChanges{
				NewBlockMetadata: &etcdraftproto.BlockMetadata{
					ConsenterIds:    []uint64{1, 2, 3},
					NextConsenterId: 4,
				},
				NewConsenters: map[uint64]*etcdraftproto.Consenter{1: c[0], 2: c[1], 3: c[2]},
				AddedNodes:    []*etcdraftproto.Consenter{c[2]},
				RemovedNodes:  []*etcdraftproto.Consenter{},
				ConfChange: &raftpb.ConfChange{
					NodeID: 3,
					Type:   raftpb.ConfChangeAddNode,
				},
			},
			Changed:     true,
			Rotated:     false,
			ExpectedErr: "",
		},
		{
			Name: "Add a node with an invalid client cert bytes",
			OldConsenters: map[uint64]*etcdraftproto.Consenter{
				1: c[0],
			},
			NewConsenters: []*etcdraftproto.Consenter{
				c[0],
				{ClientTlsCert: []byte("woops")},
			},
			Changes:     nil,
			ExpectedErr: fmt.Sprintf("parsing tls client cert: no PEM data found in cert[% x]", []byte("woops")),
		},
		{
			Name: "Add a node with an invalid server cert bytes",
			OldConsenters: map[uint64]*etcdraftproto.Consenter{
				1: c[0],
			},
			NewConsenters: []*etcdraftproto.Consenter{
				c[0],
				{ClientTlsCert: client3.Cert, ServerTlsCert: []byte("doh!")},
			},
			Changes:     nil,
			ExpectedErr: fmt.Sprintf("parsing tls server cert: no PEM data found in cert[% x]", []byte("doh!")),
		},
		{
			Name: "Add a node with an invalid tls client cert",
			OldConsenters: map[uint64]*etcdraftproto.Consenter{
				1: c[0],
			},
			NewConsenters: []*etcdraftproto.Consenter{
				c[0],
				{ClientTlsCert: client5.Cert, ServerTlsCert: client3.Cert},
			},
			Changes:     nil,
			ExpectedErr: fmt.Sprintf("verifying tls client cert with serial number %d: x509: certificate signed by unknown authority", client5.TLSCert.SerialNumber),
		},
		{
			Name: "Add a node with an invalid tls server cert",
			OldConsenters: map[uint64]*etcdraftproto.Consenter{
				1: c[0],
			},
			NewConsenters: []*etcdraftproto.Consenter{
				c[0],
				{ClientTlsCert: client3.Cert, ServerTlsCert: client5.Cert},
			},
			Changes:     nil,
			ExpectedErr: fmt.Sprintf("verifying tls server cert with serial number %d: x509: certificate signed by unknown authority", client5.TLSCert.SerialNumber),
		},
		{
			Name: "Remove a node",
			OldConsenters: map[uint64]*etcdraftproto.Consenter{
				1: c[0],
				2: c[1],
			},
			NewConsenters: []*etcdraftproto.Consenter{
				c[1],
			},
			Changes: &etcdraft.MembershipChanges{
				NewBlockMetadata: &etcdraftproto.BlockMetadata{
					ConsenterIds:    []uint64{2},
					NextConsenterId: 3,
				},
				NewConsenters: map[uint64]*etcdraftproto.Consenter{2: c[1]},
				AddedNodes:    []*etcdraftproto.Consenter{},
				RemovedNodes:  []*etcdraftproto.Consenter{c[0]},
				ConfChange: &raftpb.ConfChange{
					NodeID: 1,
					Type:   raftpb.ConfChangeRemoveNode,
				},
			},
			Changed:     true,
			Rotated:     false,
			ExpectedErr: "",
		},
		{
			Name: "Rotate a certificate",
			OldConsenters: map[uint64]*etcdraftproto.Consenter{
				1: c[0],
				2: c[1],
			},
			NewConsenters: []*etcdraftproto.Consenter{
				c[0],
				c[2],
			},
			Changes: &etcdraft.MembershipChanges{
				NewBlockMetadata: &etcdraftproto.BlockMetadata{
					ConsenterIds:    []uint64{1, 2},
					NextConsenterId: 3,
				},
				NewConsenters: map[uint64]*etcdraftproto.Consenter{1: c[0], 2: c[2]},
				AddedNodes:    []*etcdraftproto.Consenter{c[2]},
				RemovedNodes:  []*etcdraftproto.Consenter{c[1]},
				RotatedNode:   2,
			},
			Changed:     true,
			Rotated:     true,
			ExpectedErr: "",
		},
		{
			Name: "No change",
			OldConsenters: map[uint64]*etcdraftproto.Consenter{
				1: c[0],
				2: c[1],
			},
			NewConsenters: []*etcdraftproto.Consenter{
				c[0],
				c[1],
			},
			Changes: &etcdraft.MembershipChanges{
				NewBlockMetadata: &etcdraftproto.BlockMetadata{
					ConsenterIds:    []uint64{1, 2},
					NextConsenterId: 3,
				},
				NewConsenters: map[uint64]*etcdraftproto.Consenter{1: c[0], 2: c[1]},
				AddedNodes:    []*etcdraftproto.Consenter{},
				RemovedNodes:  []*etcdraftproto.Consenter{},
			},
			Changed:     false,
			Rotated:     false,
			ExpectedErr: "",
		},
		{
			Name: "More than one consenter added",
			OldConsenters: map[uint64]*etcdraftproto.Consenter{
				1: c[0],
				2: c[1],
			},
			NewConsenters: []*etcdraftproto.Consenter{
				c[0],
				c[1],
				c[2],
				c[3],
			},
			Changes:     nil,
			ExpectedErr: "update of more than one consenter at a time is not supported, requested changes: add 2 node(s), remove 0 node(s)",
		},
		{
			Name: "More than one consenter removed",
			OldConsenters: map[uint64]*etcdraftproto.Consenter{
				1: c[0],
				2: c[1],
			},
			NewConsenters: []*etcdraftproto.Consenter{
				c[2],
			},
			Changes:     nil,
			ExpectedErr: "update of more than one consenter at a time is not supported, requested changes: add 1 node(s), remove 2 node(s)",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			changes, err := etcdraft.ComputeMembershipChanges(blockMetadata, test.OldConsenters, test.NewConsenters, mockOrdererConfig)

			if test.ExpectedErr != "" {
				require.EqualError(t, err, test.ExpectedErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.Changes, changes)
				require.Equal(t, test.Changed, changes.Changed())
				require.Equal(t, test.Rotated, changes.Rotated())
			}
		})
	}
}

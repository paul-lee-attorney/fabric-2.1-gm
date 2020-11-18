/*
Copyright IBM Corp. 2016 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validation

import (
	"testing"

	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/sw"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/config/configtest"
	"github.com/paul-lee-attorney/fabric-2.1-gm/internal/configtxgen/encoder"
	"github.com/paul-lee-attorney/fabric-2.1-gm/internal/configtxgen/genesisconfig"
	"github.com/paul-lee-attorney/fabric-2.1-gm/protoutil"
	"github.com/stretchr/testify/assert"
)

func TestValidateConfigTx(t *testing.T) {
	channelID := "testchannelid"
	profile := genesisconfig.Load(genesisconfig.SampleSingleMSPChannelProfile, configtest.GetDevConfigDir())
	chCrtEnv, err := encoder.MakeChannelCreationTransaction(genesisconfig.SampleConsortiumName, nil, profile)
	if err != nil {
		t.Fatalf("MakeChannelCreationTransaction failed, err %s", err)
		return
	}

	updateResult := &cb.Envelope{
		Payload: protoutil.MarshalOrPanic(&cb.Payload{Header: &cb.Header{
			ChannelHeader: protoutil.MarshalOrPanic(&cb.ChannelHeader{
				Type:      int32(cb.HeaderType_CONFIG),
				ChannelId: channelID,
			}),
			SignatureHeader: protoutil.MarshalOrPanic(&cb.SignatureHeader{
				Creator: signerSerialized,
				Nonce:   protoutil.CreateNonceOrPanic(),
			}),
		},
			Data: protoutil.MarshalOrPanic(&cb.ConfigEnvelope{
				LastUpdate: chCrtEnv,
			}),
		}),
	}
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	updateResult.Signature, _ = signer.Sign(updateResult.Payload)
	_, txResult := ValidateTransaction(updateResult, cryptoProvider)
	if txResult != peer.TxValidationCode_VALID {
		t.Fatalf("ValidateTransaction failed, err %s", err)
		return
	}
}

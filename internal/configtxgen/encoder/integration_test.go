/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package encoder_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/gm"
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/channelconfig"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/config/configtest"
	"github.com/paul-lee-attorney/fabric-2.1-gm/internal/configtxgen/encoder"
	"github.com/paul-lee-attorney/fabric-2.1-gm/internal/configtxgen/genesisconfig"

	"github.com/pkg/errors"
)

func hasModPolicySet(groupName string, cg *cb.ConfigGroup) error {
	if cg.ModPolicy == "" {
		return errors.Errorf("group %s has empty mod_policy", groupName)
	}

	for valueName, value := range cg.Values {
		if value.ModPolicy == "" {
			return errors.Errorf("group %s has value %s with empty mod_policy", groupName, valueName)
		}
	}

	for policyName, policy := range cg.Policies {
		if policy.ModPolicy == "" {
			return errors.Errorf("group %s has policy %s with empty mod_policy", groupName, policyName)
		}
	}

	for groupName, group := range cg.Groups {
		err := hasModPolicySet(groupName, group)
		if err != nil {
			return errors.WithMessagef(err, "missing sub-mod_policy for group %s", groupName)
		}
	}

	return nil
}

var _ = Describe("Integration", func() {
	DescribeTable("successfully parses the profile",
		func(profile string) {
			config := genesisconfig.Load(profile, configtest.GetDevConfigDir())
			group, err := encoder.NewChannelGroup(config)
			Expect(err).NotTo(HaveOccurred())

			cryptoProvider, err := gm.NewDefaultSecurityLevelWithKeystore(gm.NewDummyKeyStore())
			Expect(err).NotTo(HaveOccurred())
			_, err = channelconfig.NewBundle("test", &cb.Config{
				ChannelGroup: group,
			}, cryptoProvider)
			Expect(err).NotTo(HaveOccurred())

			err = hasModPolicySet("Channel", group)
			Expect(err).NotTo(HaveOccurred())
		},
		Entry("Sample Insecure Solo Profile", genesisconfig.SampleInsecureSoloProfile),
		Entry("Sample Single MSP Solo Profile", genesisconfig.SampleSingleMSPSoloProfile),
		Entry("Sample DevMode Solo Profile", genesisconfig.SampleDevModeSoloProfile),
		Entry("Sample Insecure Kafka Profile", genesisconfig.SampleInsecureKafkaProfile),
		Entry("Sample Single MSP Kafka Profile", genesisconfig.SampleSingleMSPKafkaProfile),
		Entry("Sample DevMode Kafka Profile", genesisconfig.SampleDevModeKafkaProfile),
	)
})

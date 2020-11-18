/*
Copyright State Street Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package endorser

import (
	"testing"

	. "github.com/onsi/gomega"
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/metrics/metricsfakes"
)

func TestNewMetrics(t *testing.T) {
	gt := NewGomegaWithT(t)

	provider := &metricsfakes.Provider{}
	provider.NewHistogramReturns(&metricsfakes.Histogram{})
	provider.NewCounterReturns(&metricsfakes.Counter{})

	endorserMetrics := NewMetrics(provider)
	gt.Expect(endorserMetrics).To(Equal(&Metrics{
		ProposalDuration:         &metricsfakes.Histogram{},
		ProposalsReceived:        &metricsfakes.Counter{},
		SuccessfulProposals:      &metricsfakes.Counter{},
		ProposalValidationFailed: &metricsfakes.Counter{},
		ProposalACLCheckFailed:   &metricsfakes.Counter{},
		InitFailed:               &metricsfakes.Counter{},
		EndorsementsFailed:       &metricsfakes.Counter{},
		DuplicateTxsFailure:      &metricsfakes.Counter{},
		SimulationFailure:        &metricsfakes.Counter{},
	}))

	gt.Expect(provider.NewHistogramCallCount()).To(Equal(1))
	gt.Expect(provider.Invocations()["NewHistogram"]).To(ConsistOf([][]interface{}{
		{proposalDurationHistogramOpts},
	}))

	gt.Expect(provider.NewCounterCallCount()).To(Equal(8))
	gt.Expect(provider.Invocations()["NewCounter"]).To(ConsistOf([][]interface{}{
		{receivedProposalsCounterOpts},
		{successfulProposalsCounterOpts},
		{proposalValidationFailureCounterOpts},
		{proposalChannelACLFailureOpts},
		{initFailureCounterOpts},
		{endorsementFailureCounterOpts},
		{duplicateTxsFailureCounterOpts},
		{simulationFailureCounterOpts},
	}))
}

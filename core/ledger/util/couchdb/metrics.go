/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdb

import (
	"time"

	"github.com/paul-lee-attorney/fabric-2.1-gm/common/metrics"
)

var (
	apiProcessingTimeOpts = metrics.HistogramOpts{
		Namespace:    "couchdb",
		Subsystem:    "",
		Name:         "processing_time",
		Help:         "Time taken in seconds for the function to complete request to CouchDB",
		LabelNames:   []string{"database", "function_name", "result"},
		StatsdFormat: "%{#fqname}.%{database}.%{function_name}.%{result}",
	}
)

type stats struct {
	apiProcessingTime metrics.Histogram
}

func newStats(metricsProvider metrics.Provider) *stats {
	return &stats{
		apiProcessingTime: metricsProvider.NewHistogram(apiProcessingTimeOpts),
	}
}

func (s *stats) observeProcessingTime(startTime time.Time, dbName, functionName, result string) {
	s.apiProcessingTime.With(
		"database", dbName,
		"function_name", functionName,
		"result", result,
	).Observe(time.Since(startTime).Seconds())
}

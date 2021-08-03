package controllers

import (
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const MAX_TAG_LEN = 30
const COMPONENT = "component"
const PROFILE = "profile_controller"
const KIND = "kind"
const SEVERITY = "severity"
const SEVERITY_MAJOR = "major"

var (
	// Counter metrics
	// num of request counter vec
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "request_kf",
			Help: "Number of request_counter",
		},
		[]string{COMPONENT, KIND},
	)

	//Counter metrics for failed requests
	requestErrorCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "request_kf_failure",
		Help: "Number of request_failure_counter",
	}, []string{COMPONENT, KIND, SEVERITY})
)

func IncRequestCounter(kind string) {
	if len(kind) > MAX_TAG_LEN {
		kind = kind[0:MAX_TAG_LEN]
	}
	labels := prometheus.Labels{COMPONENT: PROFILE, KIND: kind}
	requestCounter.With(labels).Inc()
}

func IncRequestErrorCounter(kind string, severity string) {
	if len(kind) > MAX_TAG_LEN {
		kind = kind[0:MAX_TAG_LEN]
	}
	labels := prometheus.Labels{COMPONENT: PROFILE, KIND: kind, SEVERITY: severity}
	log.Errorf("Failed request with  %v", kind)
	requestErrorCounter.With(labels).Inc()
}

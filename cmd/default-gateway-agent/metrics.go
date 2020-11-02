/*
Copyright 2020 Christian Hoffmeister.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"io/ioutil"
	"time"

	"github.com/golang/glog"

	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	defaultGatewayIP = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "default_gateway_ip",
	}, []string{"ip"})
	defaultGatewayExternalIP = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "default_gateway_external_ip",
	}, []string{"ip"})
)

// ServeMetrics ...
func ServeMetrics() {
	go func() {
		for {
			UpdateMetricDefaultGatewayExternalIP()
			time.Sleep(1 * time.Minute)
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)
}

// UpdateMetricDefaultGatewayIP ...
func UpdateMetricDefaultGatewayIP(ip string) {
	defaultGatewayIP.Reset()
	if ip != "" {
		defaultGatewayIP.WithLabelValues(ip).Set(1)
	}
}

// UpdateMetricDefaultGatewayExternalIP ...
func UpdateMetricDefaultGatewayExternalIP() {
	ip := getDefaultGatewayExternalIP()
	defaultGatewayExternalIP.Reset()
	if ip != nil {
		defaultGatewayExternalIP.WithLabelValues(*ip).Set(1)
	}
}

func getDefaultGatewayExternalIP() *string {
	res, err := http.Get("https://ifconfig.me")
	if err != nil {
		glog.Errorf("unable to retrieve external IP: %v", err)
		return nil
	}
	ipBytes, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		glog.Errorf("unable to retrieve external IP: %v", err)
		return nil
	}
	ipString := string(ipBytes)
	return &ipString
}

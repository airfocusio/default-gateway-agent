/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or impliem.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/choffmeister/default-gateway-agent/cmd/default-gateway-agent/testing/fakefs"
	iptest "k8s.io/kubernetes/pkg/util/iptables/testing"
)

// turn off glog logging during tests to avoid clutter in output
func TestMain(m *testing.M) {
	flag.Set("logtostderr", "false")
	ec := m.Run()
	os.Exit(ec)
}

// returns a GatewayDaemon with empty config values and a fake iptables interface
func NewFakeGatewayDaemon() *GatewayDaemon {
	return &GatewayDaemon{
		config:   &AgentConfig{},
		iptables: iptest.NewFake(),
	}
}

// Returns a AgentConfig with config values that are the same as the default values when the
// ignoreAllReservedRangesFlag is false.
func NewAgentConfigEmpty() *AgentConfig {
	return &AgentConfig{
		IgnoreCIDRs:     []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		IgnoreLinkLocal: false,
		Gateways:        []AgentConfigGateway{},
		ResyncInterval:  Duration(1 * time.Second),
	}
}

// specs for testing config validation
var validateConfigTests = []struct {
	cfg *AgentConfig
	err error
}{
	// Empty Gateway List
	{&AgentConfig{}, nil},
	// Default Config
	{NewAgentConfigEmpty(), nil},
	// IP that doesn't match regex
	{&AgentConfig{Gateways: []AgentConfigGateway{{IP: "abcdefg"}}}, fmt.Errorf(ipParseErrFmt, "abcdefg")},
}

// tests the AgentConfig.validate method
func TestConfigValidate(t *testing.T) {
	for _, tt := range validateConfigTests {
		err := tt.cfg.validate()
		if errorToString(err) != errorToString(tt.err) {
			t.Errorf("%+v.validate() => %s, want %s", tt.cfg, errorToString(err), errorToString(tt.err))
		}
	}
}

// specs for testing loading config from fs
var syncConfigTests = []struct {
	desc string            // human readable description of the fs used for the test e.g. "no config file"
	fs   fakefs.FileSystem // filesystem interface
	err  error             // expected error from GatewayDaemon.syncConfig(fs)
	cfg  *AgentConfig      // expected values of the configuration after loading from fs
}{
	// valid yaml
	{"valid yaml file, all keys", fakefs.StringFS{File: `
ipTables:
  mark: 1
ipRule:
  table: 1
  priority: 30000
podNetwork:
  cidr: 10.244.0.0/16
gateways:
  - ip: 1.1.1.1
  - ip: 2.2.2.2
resyncInterval: 5s
`}, nil, &AgentConfig{
		IgnoreCIDRs:     []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		IgnoreLinkLocal: false,
		IPTables:        AgentConfigIPTables{Mark: 1},
		IPRule:          AgentConfigIPRule{Table: 1, Priority: 30000},
		PodNetwork:      AgentConfigPodNetwork{CIDR: "10.244.0.0/16"},
		Gateways:        []AgentConfigGateway{{IP: "1.1.1.1"}, {IP: "2.2.2.2"}},
		ResyncInterval:  Duration(5 * time.Second)}},

	// invalid yaml
	{"invalid yaml file", fakefs.StringFS{File: `*`}, fmt.Errorf("yaml: did not find expected alphabetic or numeric character"), NewAgentConfigEmpty()},

	// valid json
	{"valid json file, all keys", fakefs.StringFS{File: `
{
  "ipTables": {"mark":1},
  "ipRule": {"table":1, "priority":30000},
  "podNetwork": {"cidr":"10.244.0.0/16"},
  "gateways": [{"ip":"1.1.1.1"}, {"ip":"2.2.2.2"}],
  "resyncInterval": "5s"
}
`},
		nil, &AgentConfig{
			IgnoreCIDRs:     []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			IgnoreLinkLocal: false,
			IPTables:        AgentConfigIPTables{Mark: 1},
			IPRule:          AgentConfigIPRule{Table: 1, Priority: 30000},
			PodNetwork:      AgentConfigPodNetwork{CIDR: "10.244.0.0/16"},
			Gateways:        []AgentConfigGateway{{IP: "1.1.1.1"}, {IP: "2.2.2.2"}},
			ResyncInterval:  Duration(5 * time.Second)}},

	// invalid json
	{"invalid json file", fakefs.StringFS{File: `{*`}, fmt.Errorf("invalid character '*' looking for beginning of object key string"), NewAgentConfigEmpty()},

	// file does not exist
	{"no config file", fakefs.NotExistFS{}, nil, NewAgentConfigEmpty()}, // If the file does not exist, defaults should be used
}

// tests GatewayDaemon.syncConfig
func TestSyncConfig(t *testing.T) {
	for _, tt := range syncConfigTests {
		m := NewFakeGatewayDaemon()
		m.config = NewAgentConfigEmpty()
		err := m.syncConfig(tt.fs)
		if errorToString(err) != errorToString(tt.err) {
			t.Errorf("GatewayDaemon.syncConfig(fs: %s) => %s, want %s", tt.desc, errorToString(err), errorToString(tt.err))
		} else if !reflect.DeepEqual(m.config, tt.cfg) {
			t.Errorf("GatewayDaemon.syncConfig(fs: %s) loaded as %+v, want %+v", tt.desc, m.config, tt.cfg)
		}
	}
}

// tests GatewayDaemon.sync
func TestSync(t *testing.T) {
	var syncTests = []struct {
		desc string       // human readable description of the test
		cfg  *AgentConfig // configuration to use
		err  error        // expected error, if any. If nil, no error expected
		want string       // String expected to be sent to iptables-restore
	}{
		{
			desc: "empty config",
			cfg:  &AgentConfig{},
			want: ``,
		},
	}

	for _, tt := range syncTests {
		t.Run(tt.desc, func(t *testing.T) {
			m := NewFakeGatewayDaemon()
			m.config = tt.cfg
			m.sync()
		})
	}
}

// convert error to string, while also handling nil errors
func errorToString(err error) string {
	if err == nil {
		return "nil error"
	}
	return fmt.Sprintf("error %q", err.Error())
}

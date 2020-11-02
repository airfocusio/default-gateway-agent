/*
Copyright 2017 The Kubernetes Authors.

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
	"bytes"
	utiljson "encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/choffmeister/default-gateway-agent/cmd/default-gateway-agent/testing/fakefs"
	"github.com/sparrc/go-ping"
	"github.com/vishvananda/netlink"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/util/logs"
	utildbus "k8s.io/kubernetes/pkg/util/dbus"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	"k8s.io/kubernetes/pkg/version/verflag"
	utilexec "k8s.io/utils/exec"

	"github.com/golang/glog"
)

const (
	linkLocalCIDR = "169.254.0.0/16"
	configPath    = "/etc/config/default-gateway-agent"
)

var (
	// name of nat chain for iptables mark rules
	iptablesChain               utiliptables.Chain
	iptablesChainFlag           = flag.String("iptables-chain", "DEFAULT-GATEWAY-AGENT", `Name of iptables mangle chain for default gateway agent rules.`)
	ignoreAllReservedRangesFlag = flag.Bool("ignore-all-reserved-ranges", false, "Whether to disable mark for all IPv4 ranges reserved by RFCs.")
	cleanupFlag                 = flag.Bool("cleanup", false, "Reverts all changes made to the networking.")
)

// AgentConfigIPTables object
type AgentConfigIPTables struct {
	Mark int `json:"mark"`
}

// AgentConfigIPRule object
type AgentConfigIPRule struct {
	Table    int `json:"table"`
	Priority int `json:"priority"`
}

// AgentConfigPodNetwork object
type AgentConfigPodNetwork struct {
	CIDR string `json:"cidr"`
}

// AgentConfigGateway object
type AgentConfigGateway struct {
	IP string `json:"ip"`
}

// AgentConfig object
type AgentConfig struct {
	IgnoreCIDRs     []string              `json:"ignoreCIDRs"`
	IgnoreLinkLocal bool                  `json:"ignoreLinkLocal"`
	IPTables        AgentConfigIPTables   `json:"ipTables"`
	IPRule          AgentConfigIPRule     `json:"ipRule"`
	PodNetwork      AgentConfigPodNetwork `json:"podNetwork"`
	Gateways        []AgentConfigGateway  `json:"gateways"`
	ResyncInterval  Duration              `json:"resyncInterval"`
}

// Duration - Go's JSON unmarshaler can't handle time.ParseDuration syntax when unmarshaling into time.Duration, so we do it here
type Duration time.Duration

// UnmarshalJSON ...
func (d *Duration) UnmarshalJSON(json []byte) error {
	if json[0] == '"' {
		s := string(json[1 : len(json)-1])
		t, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(t)
		return nil
	}
	s := string(json)
	return fmt.Errorf("expected string value for unmarshal to field of type Duration, got %q", s)
}

// NewAgentConfig returns a AgentConfig with default values
func NewAgentConfig(ignoreAllReservedRanges bool) *AgentConfig {
	// RFC 1918 defines the private ip address space as 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	ignoreCIDRs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

	if ignoreAllReservedRanges {
		ignoreCIDRs = append(ignoreCIDRs,
			"100.64.0.0/10",   // RFC 6598
			"192.0.0.0/24",    // RFC 6890
			"192.0.2.0/24",    // RFC 5737
			"192.88.99.0/24",  // RFC 7526
			"198.18.0.0/15",   // RFC 6815
			"198.51.100.0/24", // RFC 5737
			"203.0.113.0/24",  // RFC 5737
			"240.0.0.0/4")     // RFC 5735, Former Class E range obsoleted by RFC 3232
	}

	return &AgentConfig{
		IgnoreCIDRs:     ignoreCIDRs,
		IgnoreLinkLocal: false,
		Gateways:        []AgentConfigGateway{},
		ResyncInterval:  Duration(1 * time.Second),
	}
}

// GatewayDaemon object
type GatewayDaemon struct {
	config   *AgentConfig
	iptables utiliptables.Interface
}

// NewGatewayDaemon returns a GatewayDaemon with default values
func NewGatewayDaemon(c *AgentConfig) *GatewayDaemon {
	execer := utilexec.New()
	dbus := utildbus.New()
	protocolv4 := utiliptables.ProtocolIpv4
	iptables := utiliptables.New(execer, dbus, protocolv4)
	return &GatewayDaemon{
		config:   c,
		iptables: iptables,
	}
}

func main() {
	flag.Parse()
	iptablesChain = utiliptables.Chain(*iptablesChainFlag)

	c := NewAgentConfig(*ignoreAllReservedRangesFlag)

	logs.InitLogs()
	defer logs.FlushLogs()

	verflag.PrintAndExitIfRequested()

	ServeMetrics()

	m := NewGatewayDaemon(c)
	if !*cleanupFlag {
		m.Run()
	} else {
		m.RunCleanup()
	}
}

// Run ...
func (m *GatewayDaemon) Run() {
	// Periodically resync to reconfigure or heal from any rule decay
	for {
		func() {
			defer time.Sleep(time.Duration(m.config.ResyncInterval))
			// resync config
			if err := m.osSyncConfig(); err != nil {
				glog.Errorf("error syncing configuration: %v", err)
				return
			}
			// resync
			if err := m.sync(); err != nil {
				glog.Errorf("error syncing gateways: %v", err)
				return
			}
		}()
	}
}

// RunCleanup ...
func (m *GatewayDaemon) RunCleanup() {
	// Periodically resync to reconfigure or heal from any rule decay
	for {
		func() {
			defer time.Sleep(time.Duration(60 * time.Minute))
			if err := m.osSyncConfig(); err != nil {
				glog.Errorf("error syncing configuration: %v", err)
				return
			}

			if err := m.cleanup(); err != nil {
				glog.Errorf("error cleaning up gateways: %v", err)
				return
			}
		}()
	}
}

func (m *GatewayDaemon) osSyncConfig() error {
	// the fakefs.FileSystem interface allows us to mock the fs from tests
	// fakefs.DefaultFS implements fakefs.FileSystem using os.Stat and io/ioutil.ReadFile
	var fs fakefs.FileSystem = fakefs.DefaultFS{}
	return m.syncConfig(fs)
}

// Syncs the config to the file at ConfigPath, or uses defaults if the file could not be found
// Error if the file is found but cannot be parsed.
func (m *GatewayDaemon) syncConfig(fs fakefs.FileSystem) error {
	var err error
	c := NewAgentConfig(*ignoreAllReservedRangesFlag)
	defer func() {
		if err == nil {
			json, _ := utiljson.Marshal(c)
			glog.V(2).Infof("using config: %s", string(json))
		}
	}()

	// check if file exists
	if _, err = fs.Stat(configPath); os.IsNotExist(err) {
		// file does not exist, use defaults
		m.config.IgnoreCIDRs = c.IgnoreCIDRs
		m.config.IgnoreLinkLocal = c.IgnoreLinkLocal
		m.config.ResyncInterval = c.ResyncInterval
		m.config.Gateways = c.Gateways
		m.config.ResyncInterval = c.ResyncInterval
		glog.V(2).Infof("no config file found at %q, using default values", configPath)
		return nil
	}
	glog.V(2).Infof("config file found at %q", configPath)

	// file exists, read and parse file
	yaml, err := fs.ReadFile(configPath)
	if err != nil {
		return err
	}

	json, err := utilyaml.ToJSON(yaml)
	if err != nil {
		return err
	}

	// Only overwrites fields provided in JSON
	if err = utiljson.Unmarshal(json, c); err != nil {
		return err
	}

	// validate configuration
	if err := c.validate(); err != nil {
		return err
	}

	// apply new config
	m.config = c
	return nil
}

func (c *AgentConfig) validate() error {
	// limit to 16 IPs to protect against really bad mistakes
	n := len(c.Gateways)
	if n > 16 {
		return fmt.Errorf("the daemon can only accept up to 16 IPs, but got %d IPs", n)
	}
	// check IPs are valid
	for _, gateway := range c.Gateways {
		if err := validateIP(gateway.IP); err != nil {
			return err
		}
	}
	// limit to 64 CIDRs (excluding link-local) to protect against really bad mistakes
	n = len(c.IgnoreCIDRs)
	if n > 64 {
		return fmt.Errorf("the daemon can only accept up to 64 CIDRs (excluding link-local), but got %d CIDRs (excluding link local)", n)
	}
	// check CIDRs are valid
	for _, cidr := range c.IgnoreCIDRs {
		if err := validateCIDR(cidr); err != nil {
			return err
		}
	}
	return nil
}

const cidrParseErrFmt = "CIDR %q could not be parsed, %v"
const cidrAlignErrFmt = "CIDR %q is not aligned to a CIDR block, ip: %q network: %q"

func validateCIDR(cidr string) error {
	// parse test
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf(cidrParseErrFmt, cidr, err)
	}
	// alignment test
	if !ip.Equal(ipnet.IP) {
		return fmt.Errorf(cidrAlignErrFmt, cidr, ip, ipnet.String())
	}
	return nil
}

const ipParseErrFmt = "IP %q could not be parsed"

func validateIP(ip string) error {
	// parse test
	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		return fmt.Errorf(ipParseErrFmt, ip)
	}
	return nil
}

func probeIP(ip net.IP) (bool, error) {
	pingTimeout := 1000 * time.Millisecond
	pinger, err := ping.NewPinger(ip.String())
	if err != nil {
		return false, fmt.Errorf("unable to ping IP %s: %v", ip, err)
	}
	pinger.SetPrivileged(true)
	pinger.Count = 3
	pinger.Interval = 100 * time.Millisecond
	pinger.Timeout = pingTimeout
	pinger.Run()
	stats := pinger.Statistics()
	return stats.PacketsRecv > 0, nil
}

func ensureFirewallMarkRules(m *GatewayDaemon) error {
	c := m.config

	// make sure our custom chain for marking exists
	_, err := m.iptables.EnsureChain(utiliptables.TableMangle, iptablesChain)
	if err != nil {
		return err
	}

	// build up lines to pass to iptables-restore
	lines := bytes.NewBuffer(nil)
	writeLine(lines, "*mangle")
	writeLine(lines, utiliptables.MakeChainLine(iptablesChain)) // effectively flushes iptablesChain atomically with rule restore

	// link-local CIDR is always non-mark
	if !c.IgnoreLinkLocal {
		writeNonMarkRule(lines, linkLocalCIDR)
	}

	// non-mark for user-provided CIDRs
	for _, cidr := range c.IgnoreCIDRs {
		writeNonMarkRule(lines, cidr)
	}

	// mark all other traffic that is not bound for a --dst-type LOCAL destination
	writeMarkRule(lines, c.PodNetwork.CIDR, c.IPTables.Mark)

	writeLine(lines, "COMMIT")

	if err := m.iptables.RestoreAll(lines.Bytes(), utiliptables.NoFlushTables, utiliptables.NoRestoreCounters); err != nil {
		return err
	}

	// ensure that any non-local in PREROUTING jumps to iptablesChain
	err = m.ensurePreroutingJump()
	if err != nil {
		return err
	}

	return nil
}

func ensurePodNetworkRule(m *GatewayDaemon) error {
	c := m.config

	existingRules, err := netlink.RuleListFiltered(netlink.FAMILY_ALL, &netlink.Rule{Table: c.IPRule.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("unable to list existing rules: %v", err)
	}

	alreadyExists := false
	for _, rule := range existingRules {
		if rule.Priority == c.IPRule.Priority && rule.Mark == c.IPTables.Mark {
			alreadyExists = true
		} else {
			glog.V(0).Infof("Deleting rule %v\n", rule)
			err := netlink.RuleDel(&rule)
			if err != nil {
				return fmt.Errorf("Unable to delete rule %v: %v", rule, err)
			}
		}
	}

	if !alreadyExists {
		rule := netlink.NewRule()
		rule.Table = c.IPRule.Table
		rule.Priority = c.IPRule.Priority
		rule.Mark = c.IPTables.Mark
		glog.V(0).Infof("Creating rule %v\n", rule)
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("unable to create rule %v: %v", rule, err)
		}
	}

	return nil
}

func ensurePodNetworkDefaultRoute(m *GatewayDaemon) error {
	c := m.config

	var gateway *AgentConfigGateway = nil
	for i, gw := range c.Gateways {
		gatewayIP := net.ParseIP(gw.IP)
		if gatewayIP == nil {
			glog.Warningf("Gateway IP %s is invalid\n", gw.IP)
			continue
		}
		reachable, err := probeIP(gatewayIP)
		if err != nil {
			glog.Warningf("Gateway %s is unreachable: %v\n", gw.IP, err)
			continue
		}
		if !reachable {
			glog.Warningf("Gateway %s is unreachable\n", gw.IP)
			continue
		}

		if gateway == nil {
			gateway = &c.Gateways[i]
		}
	}

	if gateway == nil {
		if len(c.Gateways) > 0 {
			return fmt.Errorf("no gateway is reachable")
		}
		return fmt.Errorf("no gateway was specified")
	}

	gatewayIP := net.ParseIP(gateway.IP)
	existingRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: c.IPRule.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("unable to list existing routes: %v", err)
	}

	alreadyExists := false
	for _, route := range existingRoutes {
		if route.Dst == nil {
			if route.Gw.String() == gatewayIP.String() {
				alreadyExists = true
				UpdateMetricDefaultGatewayIP(gatewayIP.String())
			} else {
				route := &netlink.Route{Gw: gatewayIP, Table: c.IPRule.Table}
				glog.V(0).Infof("Updating default route %v\n", route)
				err := netlink.RouteReplace(route)
				if err != nil {
					return fmt.Errorf("unable to create route %v: %v", route, err)
				}
				UpdateMetricDefaultGatewayIP(gatewayIP.String())
				alreadyExists = true
			}
		} else {
			glog.V(0).Infof("Deleting route %v\n", route)
			err := netlink.RouteDel(&route)
			if err != nil {
				return fmt.Errorf("Unable to delete route %v: %v", route, err)
			}
		}
	}

	if !alreadyExists {
		route := &netlink.Route{Gw: gatewayIP, Table: c.IPRule.Table}
		glog.V(0).Infof("Creating route %v\n", route)
		err := netlink.RouteAdd(route)
		if err != nil {
			return fmt.Errorf("unable to create route %v: %v", route, err)
		}
		UpdateMetricDefaultGatewayIP(gatewayIP.String())
	}

	return nil
}

func (m *GatewayDaemon) sync() error {
	err := ensureFirewallMarkRules(m)
	if err != nil {
		return err
	}
	err = ensurePodNetworkRule(m)
	if err != nil {
		return err
	}

	err = ensurePodNetworkDefaultRoute(m)
	if err != nil {
		return err
	}

	return nil
}

func (m *GatewayDaemon) cleanup() error {
	err := m.iptables.DeleteRule(utiliptables.TableMangle, utiliptables.ChainPrerouting,
		"-m", "comment", "--comment", preroutingJumpComment(),
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", string(iptablesChain))
	if err != nil {
		glog.Warningf("failed to delete %s chain %s jumps to MARK: %v\n", utiliptables.TableMangle, iptablesChain, err)
	}

	err = m.iptables.FlushChain(utiliptables.TableMangle, iptablesChain)
	if err != nil {
		glog.Warningf("failed to flush %s chain %s: %v\n", utiliptables.TableMangle, iptablesChain, err)
	}

	err = m.iptables.DeleteChain(utiliptables.TableMangle, iptablesChain)
	if err != nil {
		glog.Warningf("failed to delete %s chain %s: %v\n", utiliptables.TableMangle, iptablesChain, err)
	}

	existingRules, err := netlink.RuleListFiltered(netlink.FAMILY_ALL, &netlink.Rule{Table: m.config.IPRule.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		glog.Warningf("failed to list rules: %v\n", err)
	}
	for _, rule := range existingRules {
		err := netlink.RuleDel(&rule)
		if err != nil {
			glog.Warningf("failed to delete rule %v: %v\n", rule, err)
		}
	}

	glog.V(0).Info("Cleanup done")

	return nil
}

// NOTE(mtaufen): iptables requires names to be <= 28 characters, and somehow prepending "-m comment --comment " to this string makes it think this condition is violated
// Feel free to dig around in iptables and see if you can figure out exactly why; I haven't had time to fully trace how it parses and handle subcommands.
// If you want to investigate, get the source via `git clone git://git.netfilter.org/iptables.git`, `git checkout v1.4.21` (the version I've seen this issue on,
// though it may also happen on others), and start with `git grep XT_EXTENSION_MAXNAMELEN`.
func preroutingJumpComment() string {
	return fmt.Sprintf("default-gateway-agent: ensure mangle PREROUTING directs all non-LOCAL destination traffic to our custom %s chain", iptablesChain)
}

func (m *GatewayDaemon) ensurePreroutingJump() error {
	if _, err := m.iptables.EnsureRule(utiliptables.Append, utiliptables.TableMangle, utiliptables.ChainPrerouting,
		"-m", "comment", "--comment", preroutingJumpComment(),
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", string(iptablesChain)); err != nil {
		return fmt.Errorf("failed to ensure that %s chain %s jumps to MARK: %v", utiliptables.TableMangle, iptablesChain, err)
	}
	return nil
}

const nonMarkRuleComment = `-m comment --comment "default-gateway-agent: local traffic is not subject to MARK"`

func writeNonMarkRule(lines *bytes.Buffer, cidr string) {
	writeRule(lines, utiliptables.Append, iptablesChain, nonMarkRuleComment, "-d", cidr, "-j", "RETURN")
}

const markRuleComment = `-m comment --comment "default-gateway-agent: outbound traffic from kubernetes pod network is subject to MARK (must be last in chain)"`

func writeMarkRule(lines *bytes.Buffer, cidr string, mark int) {
	writeRule(lines, utiliptables.Append, iptablesChain, markRuleComment, "-s", cidr, "-j", "MARK", "--set-mark", strconv.Itoa(mark))
}

// Similar syntax to utiliptables.Interface.EnsureRule, except you don't pass a table
// (you must write these rules under the line with the table name)
func writeRule(lines *bytes.Buffer, position utiliptables.RulePosition, chain utiliptables.Chain, args ...string) {
	fullArgs := append([]string{string(position), string(chain)}, args...)
	writeLine(lines, fullArgs...)
}

// Join all words with spaces, terminate with newline and write to buf.
func writeLine(lines *bytes.Buffer, words ...string) {
	lines.WriteString(strings.Join(words, " ") + "\n")
}

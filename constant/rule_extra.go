package constant

import (
	"net/netip"
	"strings"
)

type RuleExtra struct {
	Network      NetWork
	SourceIPs    []*netip.Prefix
	ProcessNames []string
}

func (re *RuleExtra) NotMatchNetwork(network NetWork) bool {
	return re.Network != ALLNet && re.Network != network
}

func (re *RuleExtra) NotMatchSourceIP(srcIP netip.Addr) bool {
	if re.SourceIPs == nil {
		return false
	}

	for _, ips := range re.SourceIPs {
		if ips.Contains(srcIP) {
			return false
		}
	}
	return true
}

func (re *RuleExtra) NotMatchProcessName(processName string) bool {
	if re.ProcessNames == nil {
		return false
	}

	for _, pn := range re.ProcessNames {
		if strings.EqualFold(pn, processName) {
			return false
		}
	}
	return true
}

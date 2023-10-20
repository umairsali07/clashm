package rules

import (
	"errors"
	"net/netip"
	"strings"

	C "github.com/umairsali07/clashm/constant"
)

var (
	errPayload = errors.New("payload error")

	noResolve = "no-resolve"
)

type Base struct {
	ruleExtra *C.RuleExtra
	ruleGroup C.RuleGroup
}

func (b *Base) RuleExtra() *C.RuleExtra {
	return b.ruleExtra
}

func (b *Base) SetRuleExtra(re *C.RuleExtra) {
	b.ruleExtra = re
}

func (b *Base) SubRules() []C.Rule {
	return nil
}

func (b *Base) RuleGroups() C.RuleGroup {
	return b.ruleGroup
}

func (b *Base) AppendGroup(group string) {
	b.ruleGroup = append(b.ruleGroup, group)
}

func (b *Base) ShouldFindProcess() bool {
	return false
}

func HasNoResolve(params []string) bool {
	for _, p := range params {
		if p == noResolve {
			return true
		}
	}
	return false
}

func findNetwork(params []string) C.NetWork {
	for _, p := range params {
		if strings.EqualFold(p, "tcp") {
			return C.TCP
		} else if strings.EqualFold(p, "udp") {
			return C.UDP
		}
	}
	return C.ALLNet
}

func findSourceIPs(params []string) []*netip.Prefix {
	var ips []*netip.Prefix
	for _, p := range params {
		if p == noResolve || len(p) < 7 {
			continue
		}
		ipnet, err := netip.ParsePrefix(p)
		if err != nil {
			continue
		}
		ips = append(ips, &ipnet)
	}

	if len(ips) > 0 {
		return ips
	}
	return nil
}

func findProcessName(params []string) []string {
	var processNames []string
	for _, p := range params {
		if strings.HasPrefix(p, "P:") {
			processNames = append(processNames, strings.TrimPrefix(p, "P:"))
		}
	}

	if len(processNames) > 0 {
		return processNames
	}
	return nil
}

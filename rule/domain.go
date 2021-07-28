package rules

import (
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type Domain struct {
	domain  string
	adapter string
	network C.NetWork
}

func (d *Domain) RuleType() C.RuleType {
	return C.Domain
}

func (d *Domain) Match(metadata *C.Metadata) bool {
	if metadata.AddrType != C.AtypDomainName {
		return false
	}
	return metadata.Host == d.domain
}

func (d *Domain) Adapter() string {
	return d.adapter
}

func (d *Domain) Payload() string {
	return d.domain
}

func (d *Domain) ShouldResolveIP() bool {
	return false
}

func (d *Domain) NetWork() C.NetWork {
	return d.network
}

func NewDomain(domain string, adapter string, network C.NetWork) *Domain {
	return &Domain{
		domain:  strings.ToLower(domain),
		adapter: adapter,
		network: network,
	}
}
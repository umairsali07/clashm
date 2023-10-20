package dns

import (
	"net/netip"
	"strings"

	"github.com/umairsali07/clashm/component/geodata/router"
	"github.com/umairsali07/clashm/component/mmdb"
	"github.com/umairsali07/clashm/component/trie"
)

type fallbackIPFilter interface {
	Match(netip.Addr) bool
}

type geoipFilter struct {
	code string
}

func (gf *geoipFilter) Match(ip netip.Addr) bool {
	record, _ := mmdb.Instance().Country(ip.AsSlice())
	return !strings.EqualFold(record.Country.IsoCode, gf.code) && !ip.IsPrivate()
}

type ipnetFilter struct {
	ipnet *netip.Prefix
}

func (inf *ipnetFilter) Match(ip netip.Addr) bool {
	return inf.ipnet.Contains(ip)
}

type fallbackDomainFilter interface {
	Match(domain string) bool
}

type domainFilter struct {
	tree *trie.DomainTrie[bool]
}

func NewDomainFilter(domains []string) *domainFilter {
	df := domainFilter{tree: trie.New[bool]()}
	for _, domain := range domains {
		_ = df.tree.Insert(domain, true)
	}
	return &df
}

func (df *domainFilter) Match(domain string) bool {
	return df.tree.Search(domain) != nil
}

type geoSiteFilter struct {
	matchers []*router.DomainMatcher
}

func (gsf *geoSiteFilter) Match(domain string) bool {
	for _, matcher := range gsf.matchers {
		if matcher.ApplyDomain(domain) {
			return true
		}
	}
	return false
}

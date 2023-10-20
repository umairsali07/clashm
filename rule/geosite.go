package rules

import (
	"fmt"

	"github.com/phuslu/log"

	"github.com/umairsali07/clashm/component/geodata"
	"github.com/umairsali07/clashm/component/geodata/router"
	C "github.com/umairsali07/clashm/constant"
)

type GEOSITE struct {
	*Base
	country string
	adapter string
	matcher *router.DomainMatcher
}

func (gs *GEOSITE) RuleType() C.RuleType {
	return C.GEOSITE
}

func (gs *GEOSITE) Match(metadata *C.Metadata) bool {
	domain := metadata.Host
	if domain == "" {
		return false
	}
	return gs.matcher.ApplyDomain(domain)
}

func (gs *GEOSITE) Adapter() string {
	return gs.adapter
}

func (gs *GEOSITE) Payload() string {
	return gs.country
}

func (gs *GEOSITE) ShouldResolveIP() bool {
	return false
}

func (gs *GEOSITE) GetDomainMatcher() *router.DomainMatcher {
	return gs.matcher
}

func NewGEOSITE(country string, adapter string) (*GEOSITE, error) {
	matcher, recordsCount, err := geodata.LoadProviderByCode(country)
	if err != nil {
		return nil, fmt.Errorf("load GeoSite data error, %w", err)
	}

	count := fmt.Sprintf("%d", recordsCount)
	if recordsCount == 0 {
		count = "from cache"
	}
	if adapter == C.ScriptRuleGeoSiteTarget {
		adapter = "Script"
	}

	log.Info().
		Str("country", country).
		Str("proxy", adapter).
		Str("records", count).
		Msg("[Config] initial GeoSite rule")

	geoSite := &GEOSITE{
		Base:    &Base{},
		country: country,
		adapter: adapter,
		matcher: matcher,
	}

	return geoSite, nil
}

var _ C.Rule = (*GEOSITE)(nil)

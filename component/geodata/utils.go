package geodata

import (
	"strings"

	"github.com/umairsali07/clashm/component/geodata/router"
)

func loadGeoSiteMatcher(countryCode string, not bool) (*router.DomainMatcher, int, error) {
	geoLoaderName := "standard"
	geoLoader, err := GetGeoDataLoader(geoLoaderName)
	if err != nil {
		return nil, 0, err
	}

	domains, err := geoLoader.LoadGeoSite(countryCode)
	if err != nil {
		return nil, 0, err
	}

	/**
	linear: linear algorithm
	matcher, err := router.NewDomainMatcher(domains, not)
	mph：minimal perfect hash algorithm
	*/
	matcher, err := router.NewMphMatcherGroup(domains, not)
	if err != nil {
		return nil, 0, err
	}

	return matcher, len(domains), nil
}

var ruleProviders map[string]*router.DomainMatcher

func CleanGeoSiteCache() {
	clear(ruleProviders)
	ruleProviders = nil
}

func LoadProviderByCode(countryCode string) (matcher *router.DomainMatcher, count int, err error) {
	countryCode = strings.ToLower(countryCode)
	if ruleProviders == nil {
		ruleProviders = make(map[string]*router.DomainMatcher)
	}
	var (
		ok   bool
		not  = strings.HasPrefix(countryCode, "!")
		code = strings.TrimPrefix(countryCode, "!")
	)
	matcher, ok = ruleProviders[countryCode]
	if !ok {
		if matcher, count, err = loadGeoSiteMatcher(code, not); err == nil {
			ruleProviders[countryCode] = matcher
		}
	}
	return
}

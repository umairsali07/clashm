package geodata

import (
	"github.com/umairsali07/clashm/component/geodata/router"
)

type LoaderImplementation interface {
	LoadSite(filename, list string) ([]*router.Domain, error)
	LoadIP(filename, country string) ([]*router.CIDR, error)
}

type Loader interface {
	LoaderImplementation
	LoadGeoSite(list string) ([]*router.Domain, error)
	LoadGeoSiteWithAttr(file string, siteWithAttr string) ([]*router.Domain, error)
	LoadGeoIP(country string) ([]*router.CIDR, error)
}

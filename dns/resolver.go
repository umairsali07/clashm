package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"time"

	D "github.com/miekg/dns"
	"github.com/samber/lo"
	"golang.org/x/sync/singleflight"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/fakeip"
	"github.com/Dreamacro/clash/component/geodata/router"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
)

var _ resolver.Resolver = (*Resolver)(nil)

type dnsClient interface {
	Exchange(m *D.Msg) (msg *D.Msg, err error)
	ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error)
}

type result struct {
	Msg   *D.Msg
	Error error
}

type Resolver struct {
	ipv6                  bool
	hosts                 *trie.DomainTrie[netip.Addr]
	main                  []dnsClient
	fallback              []dnsClient
	proxyServer           []dnsClient
	remote                []dnsClient
	fallbackDomainFilters []fallbackDomainFilter
	fallbackIPFilters     []fallbackIPFilter
	group                 singleflight.Group
	lruCache              *cache.LruCache[string, *D.Msg]
	policy                *trie.DomainTrie[*Policy]
	searchDomains         []string
}

// LookupIP request with TypeA and TypeAAAA, priority return TypeA
func (r *Resolver) LookupIP(ctx context.Context, host string) (ip []netip.Addr, err error) {
	ctx1, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip6, err6 := r.lookupIP(ctx1, host, D.TypeAAAA)
		if err6 != nil {
			return
		}
		ch <- ip6
	}()

	ip, err = r.lookupIP(ctx1, host, D.TypeA)
	if err == nil {
		if resolver.IsRemote(ctx) { // force combine ipv6 list for remote resolve DNS
			if ip6, open := <-ch; open {
				ip = append(ip, ip6...)
			}
		}
		return
	}

	ip, open := <-ch
	if !open {
		return nil, resolver.ErrIPNotFound
	}

	return ip, nil
}

// ResolveIP request with TypeA and TypeAAAA, priority return TypeA
func (r *Resolver) ResolveIP(host string) (ip netip.Addr, err error) {
	ips, err := r.LookupIP(context.Background(), host)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, host)
	}
	return ips[rand.Intn(len(ips))], nil
}

// LookupIPv4 request with TypeA
func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeA)
}

// ResolveIPv4 request with TypeA
func (r *Resolver) ResolveIPv4(host string) (ip netip.Addr, err error) {
	ips, err := r.lookupIP(context.Background(), host, D.TypeA)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, host)
	}
	return ips[rand.Intn(len(ips))], nil
}

// LookupIPv6 request with TypeAAAA
func (r *Resolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeAAAA)
}

// ResolveIPv6 request with TypeAAAA
func (r *Resolver) ResolveIPv6(host string) (ip netip.Addr, err error) {
	ips, err := r.lookupIP(context.Background(), host, D.TypeAAAA)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, host)
	}
	return ips[rand.Intn(len(ips))], nil
}

func (r *Resolver) shouldIPFallback(ip netip.Addr) bool {
	for _, filter := range r.fallbackIPFilters {
		if filter.Match(ip) {
			return true
		}
	}
	return false
}

// Exchange a batch of dns request, and it uses cache
func (r *Resolver) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return r.ExchangeContext(context.Background(), m)
}

// ExchangeContext a batch of dns request with context.Context, and it uses cache
func (r *Resolver) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if len(m.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}

	var (
		q   = m.Question[0]
		key = genMsgCacheKey(ctx, q)
	)

	cacheM, expireTime, hit := r.lruCache.GetWithExpire(key)
	if hit {
		now := time.Now()
		msg = cacheM.Copy()
		if expireTime.Before(now) {
			setMsgTTL(msg, uint32(1)) // Continue fetch
			go func() {
				ctx1, cancel := context.WithTimeout(ctx, resolver.DefaultDNSTimeout)
				_, _ = r.exchangeWithoutCache(ctx1, m, q, key)
				cancel()
			}()
		} else {
			setMsgMaxTTL(msg, uint32(time.Until(expireTime).Seconds()))
		}
		return
	}
	return r.exchangeWithoutCache(ctx, m, q, key)
}

// ExchangeWithoutCache a batch of dns request, and it does NOT GET from cache
func (r *Resolver) exchangeWithoutCache(ctx context.Context, m *D.Msg, q D.Question, key string) (msg *D.Msg, err error) {
	ret, err, shared := r.group.Do(key, func() (result any, err error) {
		defer func() {
			if err != nil {
				return
			}

			msg1 := result.(*D.Msg)
			if resolver.IsProxyServer(ctx) {
				// reset proxy server ip cache expire time to at least 2 hours
				ttl := max(minTTL(msg1.Answer), 7200)
				setMsgMaxTTL(msg1, ttl)
				putMsgToCacheWithExpire(r.lruCache, key, msg1, ttl)
				return
			}

			putMsgToCache(r.lruCache, key, msg1)
		}()

		isIPReq := isIPRequest(q)
		if isIPReq {
			return r.ipExchange(ctx, m)
		}

		name := strings.TrimRight(q.Name, ".")
		if matched := r.matchPolicy(name); len(matched) != 0 {
			return r.batchExchange(ctx, matched, m)
		}
		return r.batchExchange(ctx, r.main, m)
	})

	if err == nil {
		msg = ret.(*D.Msg)
		if shared {
			msg = msg.Copy()
		}
	}

	return
}

func (r *Resolver) batchExchange(ctx context.Context, clients []dnsClient, m *D.Msg) (msg *D.Msg, err error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, resolver.DefaultDNSTimeout)
		defer cancel()
	}

	return batchExchange(ctx, clients, m)
}

func (r *Resolver) matchPolicy(domain string) []dnsClient {
	if r.policy == nil {
		return nil
	}

	if domain == "" {
		return nil
	}

	record := r.policy.Search(domain)
	if record == nil {
		return nil
	}

	p := record.Data
	return p.GetData()
}

func (r *Resolver) shouldOnlyQueryFallback(domain string) bool {
	if r.fallback == nil || r.fallbackDomainFilters == nil {
		return false
	}

	if domain == "" {
		return false
	}

	for _, df := range r.fallbackDomainFilters {
		if df.Match(domain) {
			return true
		}
	}

	return false
}

func (r *Resolver) ipExchange(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if resolver.IsRemote(ctx) && r.remote != nil {
		res := <-r.asyncExchange(ctx, r.remote, m)
		return res.Msg, res.Error
	}

	domain := r.msgToDomain(m)
	if matched := r.matchPolicy(domain); len(matched) != 0 {
		res := <-r.asyncExchange(ctx, matched, m)
		return res.Msg, res.Error
	}

	if resolver.IsProxyServer(ctx) && r.proxyServer != nil {
		res := <-r.asyncExchange(ctx, r.proxyServer, m)
		return res.Msg, res.Error
	}

	if r.shouldOnlyQueryFallback(domain) {
		res := <-r.asyncExchange(ctx, r.fallback, m)
		return res.Msg, res.Error
	}

	msgCh := r.asyncExchange(ctx, r.main, m)

	if r.fallback == nil { // directly return if no fallback servers are available
		res := <-msgCh
		msg, err = res.Msg, res.Error
		return
	}

	res := <-msgCh
	if res.Error == nil {
		if ips := msgToIP(res.Msg); len(ips) != 0 {
			if !r.shouldIPFallback(ips[0]) {
				msg = res.Msg // no need to wait for fallback result
				err = res.Error
				return msg, err
			}
		}
	}

	res = <-r.asyncExchange(ctx, r.fallback, m)
	msg, err = res.Msg, res.Error
	return
}

func (r *Resolver) lookupIP(ctx context.Context, host string, dnsType uint16) ([]netip.Addr, error) {
	ip, err := netip.ParseAddr(host)
	if err == nil {
		if dnsType != D.TypeAAAA {
			ip = ip.Unmap()
		}
		isIPv4 := ip.Is4()
		if dnsType == D.TypeAAAA && !isIPv4 {
			return []netip.Addr{ip}, nil
		} else if dnsType == D.TypeA && isIPv4 {
			return []netip.Addr{ip}, nil
		} else {
			return nil, resolver.ErrIPVersion
		}
	}

	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), dnsType)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return nil, err
	}

	ips := msgToIP(msg)
	if len(ips) != 0 {
		return ips, nil
	} else if len(r.searchDomains) == 0 {
		return nil, resolver.ErrIPNotFound
	}

	for _, domain := range r.searchDomains {
		q := &D.Msg{}
		q.SetQuestion(D.Fqdn(fmt.Sprintf("%s.%s", host, domain)), dnsType)
		msg1, err1 := r.ExchangeContext(ctx, q)
		if err1 != nil {
			return nil, err1
		}
		ips1 := msgToIP(msg1)
		if len(ips1) != 0 {
			return ips1, nil
		}
	}

	return nil, resolver.ErrIPNotFound
}

func (r *Resolver) msgToDomain(msg *D.Msg) string {
	if len(msg.Question) > 0 {
		return strings.TrimRight(msg.Question[0].Name, ".")
	}

	return ""
}

func (r *Resolver) asyncExchange(ctx context.Context, client []dnsClient, msg *D.Msg) <-chan *result {
	ch := make(chan *result, 1)
	go func() {
		res, err := r.batchExchange(ctx, client, msg)
		ch <- &result{Msg: res, Error: err}
	}()
	return ch
}

func (r *Resolver) RemoveCache(host string) {
	q := D.Question{Name: D.Fqdn(host), Qtype: D.TypeA, Qclass: D.ClassINET}
	r.lruCache.Delete(genMsgCacheKey(context.Background(), q))
	q.Qtype = D.TypeAAAA
	r.lruCache.Delete(genMsgCacheKey(context.Background(), q))
}

type NameServer struct {
	Net       string
	Addr      string
	Interface string
	Proxy     string
	IsDHCP    bool
}

type FallbackFilter struct {
	GeoIP     bool
	GeoIPCode string
	IPCIDR    []*netip.Prefix
	Domain    []string
	GeoSite   []*router.DomainMatcher
}

type Config struct {
	Main, Fallback []NameServer
	Default        []NameServer
	ProxyServer    []NameServer
	Remote         []NameServer
	IPv6           bool
	EnhancedMode   C.DNSMode
	FallbackFilter FallbackFilter
	Pool           *fakeip.Pool
	Hosts          *trie.DomainTrie[netip.Addr]
	Policy         map[string]NameServer
	SearchDomains  []string
}

func NewResolver(config Config) *Resolver {
	defaultResolver := &Resolver{
		main: transform(config.Default, nil),
		lruCache: cache.New[string, *D.Msg](
			cache.WithSize[string, *D.Msg](128),
			cache.WithStale[string, *D.Msg](true),
		),
	}

	r := &Resolver{
		ipv6: config.IPv6,
		main: transform(config.Main, defaultResolver),
		lruCache: cache.New[string, *D.Msg](
			cache.WithSize[string, *D.Msg](10240),
			cache.WithStale[string, *D.Msg](true),
		),
		hosts:         config.Hosts,
		searchDomains: config.SearchDomains,
	}

	if len(config.Fallback) != 0 {
		r.fallback = transform(config.Fallback, defaultResolver)
	}

	if len(config.ProxyServer) != 0 {
		r.proxyServer = transform(config.ProxyServer, defaultResolver)
	}

	if len(config.Remote) != 0 {
		remotes := lo.Map(config.Remote, func(item NameServer, _ int) NameServer {
			item.Proxy = "remote-resolver"
			return item
		})
		r.remote = transform(remotes, defaultResolver)
	}

	if len(config.Policy) != 0 {
		r.policy = trie.New[*Policy]()
		for domain, nameserver := range config.Policy {
			_ = r.policy.Insert(domain, NewPolicy(transform([]NameServer{nameserver}, defaultResolver)))
		}
	}

	var fallbackIPFilters []fallbackIPFilter
	if config.FallbackFilter.GeoIP {
		fallbackIPFilters = append(fallbackIPFilters, &geoipFilter{
			code: config.FallbackFilter.GeoIPCode,
		})
	}
	for _, ipnet := range config.FallbackFilter.IPCIDR {
		fallbackIPFilters = append(fallbackIPFilters, &ipnetFilter{ipnet: ipnet})
	}
	r.fallbackIPFilters = fallbackIPFilters

	var fallbackDomainFilters []fallbackDomainFilter
	if len(config.FallbackFilter.Domain) != 0 {
		fallbackDomainFilters = append(fallbackDomainFilters, NewDomainFilter(config.FallbackFilter.Domain))
	}

	if len(config.FallbackFilter.GeoSite) != 0 {
		fallbackDomainFilters = append(fallbackDomainFilters, &geoSiteFilter{
			matchers: config.FallbackFilter.GeoSite,
		})
	}
	r.fallbackDomainFilters = fallbackDomainFilters

	return r
}

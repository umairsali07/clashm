package outboundgroup

import (
	"context"
	"encoding/json"
	"time"

	"github.com/umairsali07/clashm/adapter/outbound"
	"github.com/umairsali07/clashm/common/singledo"
	"github.com/umairsali07/clashm/component/dialer"
	C "github.com/umairsali07/clashm/constant"
	"github.com/umairsali07/clashm/constant/provider"
)

type urlTestOption func(*URLTest)

func urlTestWithTolerance(tolerance uint16) urlTestOption {
	return func(u *URLTest) {
		u.tolerance = tolerance
	}
}

var _ C.ProxyAdapter = (*URLTest)(nil)

type URLTest struct {
	*outbound.Base
	tolerance  uint16
	disableUDP bool
	disableDNS bool
	fastNode   C.Proxy
	single     *singledo.Single[[]C.Proxy]
	fastSingle *singledo.Single[C.Proxy]
	providers  []provider.ProxyProvider
}

func (u *URLTest) Now() string {
	return u.fast(false).Name()
}

// DialContext implements C.ProxyAdapter
func (u *URLTest) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (c C.Conn, err error) {
	c, err = u.fast(true).DialContext(ctx, metadata, u.Base.DialOptions(opts...)...)
	if err == nil {
		c.AppendToChains(u)
	}
	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (u *URLTest) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	pc, err := u.fast(true).ListenPacketContext(ctx, metadata, u.Base.DialOptions(opts...)...)
	if err == nil {
		pc.AppendToChains(u)
	}
	return pc, err
}

// Unwrap implements C.ProxyAdapter
func (u *URLTest) Unwrap(_ *C.Metadata) C.Proxy {
	return u.fast(true)
}

func (u *URLTest) proxies(touch bool) []C.Proxy {
	elm, _, _ := u.single.Do(func() ([]C.Proxy, error) {
		return getProvidersProxies(u.providers, touch), nil
	})

	return elm
}

func (u *URLTest) fast(touch bool) C.Proxy {
	proxy, _, flag := u.fastSingle.Do(func() (C.Proxy, error) {
		proxies := u.proxies(touch)
		fast := proxies[0]
		minDelay := fast.LastDelay()
		fastNotExist := true

		for _, proxy := range proxies[1:] {
			if u.fastNode != nil && proxy.Name() == u.fastNode.Name() {
				fastNotExist = false
			}

			if !proxy.Alive() {
				continue
			}

			delay := proxy.LastDelay()
			if delay < minDelay {
				fast = proxy
				minDelay = delay
			}
		}

		// tolerance
		if u.fastNode == nil || fastNotExist || !u.fastNode.Alive() || u.fastNode.LastDelay() > fast.LastDelay()+u.tolerance {
			u.fastNode = fast
		}

		return u.fastNode, nil
	})

	if touch && flag {
		touchProvidersProxies(u.providers)
	}

	return proxy
}

// SupportUDP implements C.ProxyAdapter
func (u *URLTest) SupportUDP() bool {
	if u.disableUDP {
		return false
	}

	return u.fast(false).SupportUDP()
}

// DisableDnsResolve implements C.DisableDnsResolve
func (u *URLTest) DisableDnsResolve() bool {
	return u.disableDNS
}

// MarshalJSON implements C.ProxyAdapter
func (u *URLTest) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range u.proxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": u.Type().String(),
		"now":  u.Now(),
		"all":  all,
	})
}

func parseURLTestOption(config map[string]any) []urlTestOption {
	var opts []urlTestOption

	// tolerance
	switch tolerance := config["tolerance"].(type) {
	case int:
		opts = append(opts, urlTestWithTolerance(uint16(tolerance)))
	case string:
		if dur, err := time.ParseDuration(tolerance); err == nil {
			opts = append(opts, urlTestWithTolerance(uint16(dur.Milliseconds())))
		}
	}

	return opts
}

func NewURLTest(option *GroupCommonOption, providers []provider.ProxyProvider, options ...urlTestOption) *URLTest {
	urlTest := &URLTest{
		Base: outbound.NewBase(outbound.BaseOption{
			Name:        option.Name,
			Type:        C.URLTest,
			Interface:   option.Interface,
			RoutingMark: option.RoutingMark,
		}),
		single:     singledo.NewSingle[[]C.Proxy](defaultGetProxiesDuration),
		fastSingle: singledo.NewSingle[C.Proxy](time.Second * 10),
		providers:  providers,
		disableUDP: option.DisableUDP,
		disableDNS: option.DisableDNS,
	}

	for _, opt := range options {
		opt(urlTest)
	}

	return urlTest
}

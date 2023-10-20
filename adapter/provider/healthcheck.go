package provider

import (
	"context"
	"time"

	"github.com/samber/lo"
	"go.uber.org/atomic"

	"github.com/umairsali07/clashm/common/batch"
	C "github.com/umairsali07/clashm/constant"
)

const (
	defaultURLTestTimeout = time.Second * 5
)

type HealthCheck struct {
	url       string
	proxies   []C.Proxy
	proxiesFn func() []C.Proxy
	interval  time.Duration
	lazy      bool
	lastTouch *atomic.Int64
	ticker    *time.Ticker
	done      chan struct{}
}

func (hc *HealthCheck) process() {
	defer func() {
		_ = recover()
	}()

	if hc.ticker != nil {
		return
	}

	hc.ticker = time.NewTicker(hc.interval)

	for {
		select {
		case <-hc.ticker.C:
			now := time.Now().UnixNano()
			if !hc.lazy || now-hc.lastTouch.Load() < int64(hc.interval) {
				hc.checkAll()
			} else { // lazy but still need to check not alive proxies
				notAliveProxies := lo.Filter(hc.getProxies(), func(proxy C.Proxy, _ int) bool {
					return !proxy.Alive()
				})
				if len(notAliveProxies) != 0 {
					hc.check(notAliveProxies)
				}
			}
		case <-hc.done:
			hc.ticker.Stop()
			hc.ticker = nil
			return
		}
	}
}

func (hc *HealthCheck) setProxy(proxies []C.Proxy) {
	hc.proxies = proxies
}

func (hc *HealthCheck) setProxyFn(proxiesFn func() []C.Proxy) {
	hc.proxiesFn = proxiesFn
}

func (hc *HealthCheck) auto() bool {
	return hc.interval != 0
}

func (hc *HealthCheck) touch() {
	hc.lastTouch.Store(time.Now().UnixNano())
}

func (hc *HealthCheck) getProxies() []C.Proxy {
	if hc.proxiesFn != nil {
		return hc.proxiesFn()
	}
	return hc.proxies
}

func (hc *HealthCheck) checkAll() {
	hc.check(hc.getProxies())
}

func (hc *HealthCheck) check(proxies []C.Proxy) {
	if len(proxies) == 0 {
		return
	}
	b, _ := batch.New[bool](context.Background(), batch.WithConcurrencyNum[bool](10))
	for _, proxy := range proxies {
		p := proxy
		b.Go(p.Name(), func() (bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
			defer cancel()
			_, _, _ = p.URLTest(ctx, hc.url)
			return false, nil
		})
	}
	b.Wait()
}

func (hc *HealthCheck) close() {
	if hc.ticker != nil {
		hc.done <- struct{}{}
	}
	hc.interval = 0
	hc.proxiesFn = nil
	hc.proxies = nil
}

func NewHealthCheck(proxies []C.Proxy, url string, interval time.Duration, lazy bool) *HealthCheck {
	if interval < 0 {
		interval = 0
	}
	return &HealthCheck{
		proxies:   proxies,
		url:       url,
		interval:  interval,
		lazy:      lazy,
		lastTouch: atomic.NewInt64(0),
		done:      make(chan struct{}, 1),
	}
}

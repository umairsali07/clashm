package commons

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/phuslu/log"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/umairsali07/clashm/common/nnip"
	C "github.com/umairsali07/clashm/constant"
	"github.com/umairsali07/clashm/listener/tun/device"
	"github.com/umairsali07/clashm/listener/tun/device/tun"
)

var (
	wintunInterfaceName          string
	unicastAddressChangeCallback *winipcfg.UnicastAddressChangeCallback
	unicastAddressChangeLock     sync.Mutex
)

func ConfigInterfaceAddress(dev device.Device, addr netip.Prefix, forceMTU int, autoRoute bool) error {
	retryOnFailure := services.StartedAtBoot()
	tryTimes := 0
	var err error
startOver:
	if tryTimes > 0 {
		log.Info().
			Err(err).
			Dur("time", windows.DurationSinceBoot()).
			Msg("[TUN] retrying interface configuration after failure, because system just booted")
		time.Sleep(time.Second)
		retryOnFailure = retryOnFailure && tryTimes < 15
	}
	tryTimes++

	var (
		luid       = winipcfg.LUID(dev.(*tun.TUN).LUID())
		ip         = addr.Masked().Addr().Next()
		gw         = ip.Next()
		addresses  = []netip.Prefix{netip.PrefixFrom(ip, addr.Bits())}
		dnsAddress = []netip.Addr{gw}

		family4       = winipcfg.AddressFamily(windows.AF_INET)
		familyV6      = winipcfg.AddressFamily(windows.AF_INET6)
		currentFamily = winipcfg.AddressFamily(windows.AF_INET6)
	)

	if addr.Addr().Is4() {
		currentFamily = winipcfg.AddressFamily(windows.AF_INET)
	}

	err = luid.FlushRoutes(windows.AF_INET6)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return err
	}
	err = luid.FlushIPAddresses(windows.AF_INET6)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return err
	}
	err = luid.FlushDNS(windows.AF_INET6)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return err
	}
	err = luid.FlushDNS(windows.AF_INET)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return err
	}

	foundDefault4 := false
	foundDefault6 := false

	if autoRoute {
		var (
			allowedIPs []netip.Prefix

			// add default
			routeArr = []string{"0.0.0.0/0"}
		)

		for _, route := range routeArr {
			allowedIPs = append(allowedIPs, netip.MustParsePrefix(route))
		}

		estimatedRouteCount := len(allowedIPs)
		routes := make(map[winipcfg.RouteData]bool, estimatedRouteCount)

		for _, allowedip := range allowedIPs {
			route := winipcfg.RouteData{
				Destination: allowedip.Masked(),
				Metric:      0,
			}
			if allowedip.Addr().Is4() {
				if allowedip.Bits() == 0 {
					foundDefault4 = true
				}
				route.NextHop = netip.IPv4Unspecified()
			} else if allowedip.Addr().Is6() {
				if allowedip.Bits() == 0 {
					foundDefault6 = true
				}
				route.NextHop = netip.IPv6Unspecified()
			}
			routes[route] = true
		}

		deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
		for route := range routes {
			r := route
			deduplicatedRoutes = append(deduplicatedRoutes, &r)
		}

		// add gateway
		deduplicatedRoutes = append(deduplicatedRoutes, &winipcfg.RouteData{
			Destination: addr.Masked(),
			NextHop:     gw,
			Metric:      0,
		})

		err = luid.SetRoutesForFamily(currentFamily, deduplicatedRoutes)
		if err == windows.ERROR_NOT_FOUND && retryOnFailure {
			goto startOver
		} else if err != nil {
			return fmt.Errorf("unable to set routes: %w", err)
		}
	}

	err = luid.SetIPAddressesForFamily(currentFamily, addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(currentFamily, addresses)
		err = luid.SetIPAddressesForFamily(currentFamily, addresses)
	}
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set ips: %w", err)
	}

	var ipif *winipcfg.MibIPInterfaceRow
	ipif, err = luid.IPInterface(family4)
	if err != nil {
		return err
	}
	ipif.ForwardingEnabled = true
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif.DadTransmits = 0
	ipif.ManagedAddressConfigurationSupported = false
	ipif.OtherStatefulConfigurationSupported = false
	if forceMTU > 0 {
		ipif.NLMTU = uint32(forceMTU)
	}
	if foundDefault4 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	err = ipif.Set()
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set metric and MTU: %w", err)
	}

	var ipif6 *winipcfg.MibIPInterfaceRow
	ipif6, err = luid.IPInterface(familyV6)
	if err != nil {
		return err
	}
	ipif6.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif6.DadTransmits = 0
	ipif6.ManagedAddressConfigurationSupported = false
	ipif6.OtherStatefulConfigurationSupported = false
	if forceMTU > 0 {
		ipif6.NLMTU = uint32(forceMTU)
	}
	if foundDefault6 {
		ipif6.UseAutomaticMetric = false
		ipif6.Metric = 0
	}
	err = ipif6.Set()
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set v6 metric and MTU: %w", err)
	}

	err = luid.SetDNS(family4, dnsAddress, nil)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set DNS %s %s: %w", dnsAddress[0].String(), "nil", err)
	}

	wintunInterfaceName = dev.Name()

	return nil
}

func StartDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	defer monitorMux.Unlock()

	if unicastAddressChangeCallback != nil {
		return
	}

	var err error
	unicastAddressChangeCallback, err = winipcfg.RegisterUnicastAddressChangeCallback(unicastAddressChange)
	if err != nil {
		log.Error().Err(err).Msg("[Route] register uni-cast address change callback failed")
		return
	}

	tunStatus = C.TunEnabled

	log.Info().Msg("[Route] register uni-cast address change callback")
}

func StopDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	defer monitorMux.Unlock()

	if unicastAddressChangeCallback == nil || tunStatus == C.TunPaused {
		return
	}

	_ = unicastAddressChangeCallback.Unregister()
	unicastAddressChangeCallback = nil
	tunChangeCallback = nil
	tunStatus = C.TunDisabled
}

func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []netip.Prefix) {
	if len(addresses) == 0 {
		return
	}
	addrHash := make(map[netip.Addr]bool, len(addresses))
	for i := range addresses {
		addrHash[addresses[i].Addr()] = true
	}
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, ifaceM := range interfaces {
		if ifaceM.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for address := ifaceM.FirstUnicastAddress; address != nil; address = address.Next {
			if ip := nnip.IpToAddr(address.Address.IP()); addrHash[ip] {
				prefix := netip.PrefixFrom(ip, int(address.OnLinkPrefixLength))
				log.Info().
					Str("address", prefix.String()).
					Str("interface", ifaceM.FriendlyName()).
					Msg("[TUN] cleaning up stale")
				_ = ifaceM.LUID.DeleteIPAddress(prefix)
			}
		}
	}
}

func defaultRouteInterface() (*DefaultInterface, error) {
	ifaceM, err := getAutoDetectInterfaceByFamily(winipcfg.AddressFamily(windows.AF_INET))
	if err == nil {
		return ifaceM, err
	}

	return getAutoDetectInterfaceByFamily(winipcfg.AddressFamily(windows.AF_INET6))
}

func getAutoDetectInterfaceByFamily(family winipcfg.AddressFamily) (*DefaultInterface, error) {
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return nil, err
	}

	var destination netip.Prefix
	if family == windows.AF_INET {
		destination = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	} else {
		destination = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}

	for _, ifaceM := range interfaces {
		if ifaceM.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		ifname := ifaceM.FriendlyName()

		if wintunInterfaceName == ifname || ifaceM.FirstUnicastAddress == nil {
			continue
		}

		for gatewayAddress := ifaceM.FirstGatewayAddress; gatewayAddress != nil; gatewayAddress = gatewayAddress.Next {
			nextHop := nnip.IpToAddr(gatewayAddress.Address.IP())

			if _, err = ifaceM.LUID.Route(destination, nextHop); err == nil {
				return &DefaultInterface{
					Name:    ifname,
					Index:   int(ifaceM.IfIndex),
					IP:      nnip.IpToAddr(ifaceM.FirstUnicastAddress.Address.IP()),
					Gateway: nextHop,
				}, nil
			}
		}
	}

	return nil, errInterfaceNotFound
}

func unicastAddressChange(_ winipcfg.MibNotificationType, _ *winipcfg.MibUnicastIPAddressRow) {
	unicastAddressChangeLock.Lock()
	defer unicastAddressChangeLock.Unlock()

	onChangeDefaultRoute()
}

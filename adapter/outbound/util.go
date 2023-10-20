package outbound

import (
	"net"
	"time"

	"github.com/umairsali07/clashm/common/pool"
	"github.com/umairsali07/clashm/component/resolver"
	C "github.com/umairsali07/clashm/constant"
	"github.com/umairsali07/clashm/transport/socks5"
)

func tcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}

func serializesSocksAddr(metadata *C.Metadata) []byte {
	buf := pool.BufferWriter{}

	addrType := metadata.AddrType()
	buf.PutUint8(uint8(addrType))

	switch addrType {
	case socks5.AtypDomainName:
		buf.PutUint8(uint8(len(metadata.Host)))
		buf.PutString(metadata.Host)
	case socks5.AtypIPv4, socks5.AtypIPv6:
		buf.PutSlice(metadata.DstIP.AsSlice())
	}

	buf.PutUint16be(uint16(metadata.DstPort))
	return buf.Bytes()
}

func resolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ip, err := resolver.ResolveProxyServerHost(host)
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr(network, net.JoinHostPort(ip.String(), port))
}

func safeConnClose(c net.Conn, err error) {
	if err != nil && c != nil {
		_ = c.Close()
	}
}

package outbound

import (
	"context"
	"net"
	"net/netip"

	"github.com/umairsali07/clashm/component/dialer"
	C "github.com/umairsali07/clashm/constant"
)

var _ C.ProxyAdapter = (*Direct)(nil)

type Direct struct {
	*Base
}

// DialContext implements C.ProxyAdapter
func (d *Direct) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	opts = append(opts, dialer.WithDirect())
	c, err := dialer.DialContext(ctx, "tcp", metadata.RemoteAddress(), d.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}

	tcpKeepAlive(c)

	if !metadata.Resolved() && c.RemoteAddr() != nil {
		if h, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
			metadata.DstIP = netip.MustParseAddr(h)
		}
	}

	return NewConn(c, d), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (d *Direct) ListenPacketContext(ctx context.Context, _ *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	opts = append(opts, dialer.WithDirect())
	pc, err := dialer.ListenPacket(ctx, "udp", "", d.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(&directPacketConn{pc}, d), nil
}

// DisableDnsResolve implements C.DisableDnsResolve
func (d *Direct) DisableDnsResolve() bool {
	return true
}

type directPacketConn struct {
	net.PacketConn
}

func NewDirect() *Direct {
	return &Direct{
		Base: &Base{
			name: "DIRECT",
			tp:   C.Direct,
			udp:  true,
		},
	}
}

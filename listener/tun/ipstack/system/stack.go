package system

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/phuslu/log"
	"gvisor.dev/gvisor/pkg/buffer"

	"github.com/umairsali07/clashm/adapter/inbound"
	"github.com/umairsali07/clashm/common/nnip"
	"github.com/umairsali07/clashm/common/pool"
	C "github.com/umairsali07/clashm/constant"
	"github.com/umairsali07/clashm/listener/tun/device"
	"github.com/umairsali07/clashm/listener/tun/ipstack"
	D "github.com/umairsali07/clashm/listener/tun/ipstack/commons"
	"github.com/umairsali07/clashm/listener/tun/ipstack/system/mars"
	"github.com/umairsali07/clashm/listener/tun/ipstack/system/mars/nat"
)

type sysStack struct {
	stack  io.Closer
	device device.Device

	closed bool
	once   sync.Once
	wg     sync.WaitGroup
}

func (s *sysStack) Close() error {
	D.StopDefaultInterfaceChangeMonitor()

	defer func() {
		if s.device != nil {
			_ = s.device.Close()
		}
	}()

	s.closed = true

	err := s.stack.Close()

	s.wg.Wait()

	return err
}

func New(device device.Device, dnsHijack []C.DNSUrl, tunAddress netip.Prefix, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.Stack, error) {
	var (
		gateway   = tunAddress.Masked().Addr().Next()
		portal    = gateway.Next()
		broadcast = nnip.UnMasked(tunAddress)
	)

	stack, err := mars.StartListener(device, gateway, portal, broadcast)
	if err != nil {
		_ = device.Close()

		return nil, err
	}

	ipStack := &sysStack{stack: stack, device: device}

	dnsAddr := dnsHijack

	tcp := func() {
		defer func(tcp *nat.TCP) {
			_ = tcp.Close()
		}(stack.TCP())

		for {
			conn, err0 := stack.TCP().Accept()
			if err0 != nil {
				if ipStack.closed {
					break
				}
				log.Warn().
					Err(err0).
					Msg("[Stack] accept connection failed")
				continue
			}

			lAddrPort := conn.LocalAddr().(*net.TCPAddr).AddrPort()
			rAddrPort := conn.RemoteAddr().(*net.TCPAddr).AddrPort()

			if rAddrPort.Addr().IsLoopback() {
				_ = conn.Close()

				continue
			}

			if D.ShouldHijackDns(dnsAddr, rAddrPort, "tcp") {
				go func(dnsConn net.Conn, addr string) {
					log.Debug().Str("addr", addr).Msg("[TUN] hijack tcp dns")

					defer func(c net.Conn) {
						_ = c.Close()
					}(dnsConn)

					err1 := dnsConn.SetReadDeadline(time.Now().Add(C.DefaultTCPTimeout))
					if err1 != nil {
						return
					}

					buf := pool.NewBuffer()
					defer buf.Release()

					length, err1 := buf.ReadUint16be(dnsConn)
					if err1 != nil {
						return
					}

					_, err1 = buf.ReadFullFrom(dnsConn, int64(length))
					if err1 != nil {
						return
					}

					msg, err1 := D.RelayDnsPacket(buf.Bytes())
					if err1 != nil {
						return
					}

					buf.Reset()

					length = uint16(len(msg))
					_ = binary.Write(buf, binary.BigEndian, length)

					_, err1 = buf.Write(msg)
					if err1 != nil {
						return
					}

					_, _ = buf.WriteTo(dnsConn)
				}(conn, rAddrPort.String())

				continue
			}

			tcpIn <- inbound.NewSocketBy(conn, lAddrPort, rAddrPort, C.TUN)
		}

		ipStack.wg.Done()
	}

	udp := func() {
		defer func(udp *nat.UDP) {
			_ = udp.Close()
		}(stack.UDP())

		buf := make([]byte, 65535)
		for {
			n, lAddrPort, rAddrPort, err0 := stack.UDP().ReadFrom(buf)
			if err0 != nil {
				if ipStack.closed {
					break
				}

				log.Warn().Err(err0).Msg("[Stack] accept udp failed")
				continue
			}

			if rAddrPort.Addr().IsLoopback() || rAddrPort.Addr() == gateway {
				continue
			}

			data := buffer.NewViewWithData(buf[:n])

			if D.ShouldHijackDns(dnsAddr, rAddrPort, "udp") {
				go func(st *mars.StackListener, dat *buffer.View, rap, lap netip.AddrPort) {
					log.Debug().Str("addr", rap.String()).Msg("[TUN] hijack udp dns")

					defer dat.Release()

					msg, err1 := D.RelayDnsPacket(dat.AsSlice())
					if err1 != nil {
						return
					}

					_, _ = st.UDP().WriteTo(msg, rap, lap)
				}(stack, data, rAddrPort, lAddrPort)

				continue
			}

			pkt := &packet{
				sender: stack.UDP(),
				lAddr:  lAddrPort,
				data:   data,
			}

			select {
			case udpIn <- inbound.NewPacketBy(pkt, lAddrPort, rAddrPort, C.TUN):
			default:
				log.Debug().
					NetIPAddrPort("lAddrPort", lAddrPort).
					NetIPAddrPort("rAddrPort", rAddrPort).
					Msg("[Stack] drop udp packet, because inbound queue is full")
				pkt.Drop()
			}
		}

		ipStack.wg.Done()
	}

	ipStack.once.Do(func() {
		ipStack.wg.Add(2)
		go tcp()
		go udp()
	})

	return ipStack, nil
}

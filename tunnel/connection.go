package tunnel

import (
	"errors"
	"net"
	"net/netip"
	"time"

	N "github.com/umairsali07/clashm/common/net"
	"github.com/umairsali07/clashm/common/pool"
	C "github.com/umairsali07/clashm/constant"
)

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, metadata *C.Metadata) error {
	addr := metadata.UDPAddr()
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(packet C.UDPPacket, pc net.PacketConn, key, rKey string, oAddr, fAddr netip.Addr) {
	buf := pool.Get(pool.UDPBufferSize)
	defer func() {
		_ = pc.Close()
		natTable.Delete(key)
		_ = pool.Put(buf)

		if rKey != "" {
			addrTable.Delete(rKey)
		}
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}

		fromUDPAddr := *(from.(*net.UDPAddr))
		if fAddr.IsValid() {
			fromAddr, _ := netip.AddrFromSlice(fromUDPAddr.IP)
			fromAddr = fromAddr.Unmap()
			if oAddr == fromAddr {
				fromUDPAddr.IP = fAddr.AsSlice()
				fromUDPAddr.Zone = fAddr.Zone()
			}
		}

		_, err = packet.WriteBack(buf[:n], &fromUDPAddr)
		if err != nil {
			return
		}
	}
}

func handleSocket(ctx C.ConnContext, outbound net.Conn) {
	N.Relay(ctx.Conn(), outbound)
}

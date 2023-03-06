// Package iobased provides the implementation of io.ReadWriter
// based data-link layer endpoints.
package iobased

import (
	"context"
	"errors"
	"os"
	"sync"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	dev "github.com/Dreamacro/clash/listener/tun/device"
)

const (
	// Queue length for outbound packet, arriving for read. Overflow
	// causes packet drops.
	defaultOutQueueLen = 1 << 9
)

// Endpoint implements the interface of stack.LinkEndpoint from io.ReadWriter.
type Endpoint struct {
	*channel.Endpoint

	// rw is the io.ReadWriter for reading and writing packets.
	rw dev.Device

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// offset can be useful when perform TUN device I/O with TUN_PI enabled.
	offset int

	// once is used to perform the init action once when attaching.
	once sync.Once

	// wg keeps track of running goroutines.
	wg sync.WaitGroup
}

// New returns stack.LinkEndpoint(.*Endpoint) and error.
func New(rw dev.Device, mtu uint32, offset int) (*Endpoint, error) {
	if mtu == 0 {
		return nil, errors.New("MTU size is zero")
	}

	if rw == nil {
		return nil, errors.New("RW interface is nil")
	}

	if offset < 0 {
		return nil, errors.New("offset must be non-negative")
	}

	return &Endpoint{
		Endpoint: channel.New(defaultOutQueueLen, mtu, ""),
		rw:       rw,
		mtu:      mtu,
		offset:   offset,
	}, nil
}

func (e *Endpoint) Wait() {
	e.wg.Wait()
}

// Attach launches the goroutine that reads packets from io.Reader and
// dispatches them via the provided dispatcher.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Endpoint.Attach(dispatcher)
	e.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		e.wg.Add(2)
		go func() {
			e.outboundLoop(ctx)
			e.wg.Done()
		}()
		go func() {
			e.dispatchLoop(cancel)
			e.wg.Done()
		}()
	})
}

// dispatchLoop dispatches packets to upper layer.
func (e *Endpoint) dispatchLoop(cancel context.CancelFunc) {
	// Call cancel() to ensure (*Endpoint).outboundLoop(context.Context) exits
	// gracefully after (*Endpoint).dispatchLoop(context.CancelFunc) returns.
	defer cancel()

	var (
		readErr   error
		device    = e.rw
		offset    = e.offset
		mtu       = int(e.mtu)
		count     = 0
		batchSize = device.BatchSize()
		buffs     = make([][]byte, batchSize)
		sizes     = make([]int, batchSize)
	)

	for i := range buffs {
		buffs[i] = make([]byte, mtu+offset)
	}

	for {
		count, readErr = device.Read(buffs, sizes, offset)
		for i := 0; i < count; i++ {
			if sizes[i] < 1 {
				continue
			}

			if !e.IsAttached() {
				continue /* unattached, drop packet */
			}

			data := buffs[i][offset : offset+sizes[i]]

			var p tcpip.NetworkProtocolNumber
			switch header.IPVersion(data) {
			case header.IPv4Version:
				p = header.IPv4ProtocolNumber
			case header.IPv6Version:
				p = header.IPv6ProtocolNumber
			default:
				continue
			}

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: bufferv2.MakeWithData(data),
			})

			e.InjectInbound(p, pkt)

			pkt.DecRef()
		}

		if readErr != nil {
			if errors.Is(readErr, os.ErrClosed) {
				return
			}
			continue
		}
	}
}

// outboundLoop reads outbound packets from channel, and then it calls
// writePacket to send those packets back to lower layer.
func (e *Endpoint) outboundLoop(ctx context.Context) {
	for {
		pkt := e.ReadContext(ctx)
		if pkt.IsNil() {
			break
		}
		e.writePacket(pkt)
	}
}

// writePacket writes outbound packets to the io.Writer.
func (e *Endpoint) writePacket(pkt stack.PacketBufferPtr) tcpip.Error {
	pktBuff := pkt.ToBuffer()

	defer func() {
		pktBuff.Release()
		pkt.DecRef()
	}()

	offset := e.offset
	if offset > 0 {
		_ = pktBuff.Prepend(bufferv2.NewViewSize(offset))
	}

	if _, err := e.rw.Write([][]byte{pktBuff.Flatten()}, offset); err != nil {
		return &tcpip.ErrInvalidEndpointState{}
	}
	return nil
}

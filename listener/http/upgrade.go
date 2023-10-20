package http

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/umairsali07/clashm/adapter/inbound"
	N "github.com/umairsali07/clashm/common/net"
	C "github.com/umairsali07/clashm/constant"
	"github.com/umairsali07/clashm/transport/socks5"
)

func isUpgradeRequest(req *http.Request) bool {
	for _, header := range req.Header["Connection"] {
		for _, elm := range strings.Split(header, ",") {
			if strings.EqualFold(strings.TrimSpace(elm), "Upgrade") {
				return true
			}
		}
	}

	return false
}

func HandleUpgrade(localConn net.Conn, serverConn *N.BufferedConn, request *http.Request, in chan<- C.ConnContext) (resp *http.Response) {
	removeProxyHeaders(request.Header)
	RemoveExtraHTTPHostPort(request)

	if serverConn == nil {
		address := request.Host
		if _, _, err := net.SplitHostPort(address); err != nil {
			port := "80"
			if request.TLS != nil {
				port = "443"
			}
			address = net.JoinHostPort(address, port)
		}

		dstAddr := socks5.ParseAddr(address)
		if dstAddr == nil {
			return
		}

		left, right := net.Pipe()

		in <- inbound.NewHTTP(dstAddr, localConn.RemoteAddr(), localConn.LocalAddr(), right)

		serverConn = N.NewBufferedConn(left)

		defer func() {
			_ = serverConn.Close()
		}()
	}

	err := request.Write(serverConn)
	if err != nil {
		_ = localConn.Close()
		return
	}

	resp, err = http.ReadResponse(serverConn.Reader(), request)
	if err != nil {
		_ = localConn.Close()
		return
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		removeProxyHeaders(resp.Header)

		err = localConn.SetReadDeadline(time.Time{}) // set to not time out
		if err != nil {
			return
		}

		err = resp.Write(localConn)
		if err != nil {
			return
		}

		N.Relay(serverConn, localConn) // blocking here
		_ = localConn.Close()
		resp = nil
	}
	return
}

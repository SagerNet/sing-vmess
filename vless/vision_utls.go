//go:build with_utls

package vless

import (
	"net"
	"reflect"
	"unsafe"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing/common"
)

func init() {
	tlsRegistry = append(tlsRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr) {
		uConn, loaded := common.Cast[*utls.UConn](conn)
		if loaded {
			return true, uConn.NetConn(), reflect.TypeOf(uConn.Conn).Elem(), uintptr(unsafe.Pointer(uConn.Conn))
		}
		tlsConn, loaded := common.Cast[*utls.Conn](conn)
		if loaded {
			return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn).Elem(), uintptr(unsafe.Pointer(tlsConn))
		}
		return
	})
}

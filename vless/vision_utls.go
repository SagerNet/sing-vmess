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
		tlsConn, loaded := common.Cast[*utls.UConn](conn)
		if !loaded {
			return
		}
		return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn.Conn).Elem(), uintptr(unsafe.Pointer(tlsConn.Conn))
	})
}

package vmess

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ N.EarlyWriter = (*XUDPConn)(nil)

type XUDPConn struct {
	net.Conn
	writer         N.ExtendedWriter
	destination    M.Socksaddr
	requestWritten bool
}

func NewXUDPConn(conn net.Conn, destination M.Socksaddr) *XUDPConn {
	return &XUDPConn{
		Conn:        conn,
		writer:      bufio.NewExtendedWriter(conn),
		destination: destination,
	}
}

func (c *XUDPConn) Read(p []byte) (n int, err error) {
	n, _, err = c.ReadFrom(p)
	return
}

func (c *XUDPConn) Write(p []byte) (n int, err error) {
	return c.WriteTo(p, c.destination)
}

func (c *XUDPConn) RemoteAddr() net.Addr {
	return c.destination
}

func (c *XUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	var destination M.Socksaddr
	destination, err = c.ReadPacket(buffer)
	if err != nil {
		return
	}
	if destination.IsFqdn() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	n = buffer.Len()
	return
}

func (c *XUDPConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	start := buffer.Start()
	for {
		var header [6]byte
		_, err = io.ReadFull(c.Conn, header[:])
		if err != nil {
			return
		}
		length := binary.BigEndian.Uint16(header[:2])
		if length < 4 {
			return M.Socksaddr{}, E.New("invalid frame length: ", length)
		}
		status := header[4]
		option := header[5]
		switch status {
		case StatusNew:
			return M.Socksaddr{}, E.New("unexpected frame new")
		case StatusKeep:
			if length > 4 {
				metaBuffer := buf.NewSize(int(length) - 4)
				_, err = metaBuffer.ReadFullFrom(c.Conn, int(length)-4)
				if err != nil {
					metaBuffer.Release()
					return
				}
				_, err = metaBuffer.ReadByte()
				if err != nil {
					metaBuffer.Release()
					return
				}
				destination, err = AddressSerializer.ReadAddrPort(metaBuffer)
				metaBuffer.Release()
				if err != nil {
					return
				}
				destination = destination.Unwrap()
			} else {
				destination = c.destination
			}
		case StatusEnd:
			return M.Socksaddr{}, io.EOF
		case StatusKeepAlive:
			if length > 4 {
				_, err = io.CopyN(io.Discard, c.Conn, int64(length-4))
				if err != nil {
					return
				}
			}
		default:
			return M.Socksaddr{}, E.New("unexpected frame: ", status)
		}
		if option&OptionError == OptionError {
			return M.Socksaddr{}, E.Cause(net.ErrClosed, "remote closed")
		}
		if option&OptionData == OptionData {
			_, err = io.ReadFull(c.Conn, header[:2])
			if err != nil {
				return
			}
			dataLen := int(binary.BigEndian.Uint16(header[:2]))
			if status == StatusKeepAlive {
				_, err = io.CopyN(io.Discard, c.Conn, int64(dataLen))
				if err != nil {
					return
				}
				continue
			}
			buffer.Resize(start, 0)
			if dataLen > buffer.FreeLen() {
				_, err = io.CopyN(io.Discard, c.Conn, int64(dataLen))
				if err != nil {
					return
				}
				return M.Socksaddr{}, io.ErrShortBuffer
			}
			_, err = buffer.ReadFullFrom(c.Conn, dataLen)
			return
		}
		buffer.Resize(start, 0)
	}
}

func (c *XUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return bufio.WritePacketBuffer(c, buf.As(p), M.SocksaddrFromNet(addr))
}

func (c *XUDPConn) frontHeadroom(addrLen int) int {
	if !c.requestWritten {
		var headerLen int
		headerLen += 2 // frame len
		headerLen += 5 // frame header
		headerLen += addrLen
		headerLen += 2 // payload len
		return headerLen
	} else {
		return 7 + addrLen + 2
	}
}

func (c *XUDPConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	dataLen := buffer.Len()
	addrLen := M.SocksaddrSerializer.AddrPortLen(destination)
	if !c.requestWritten {
		header := buf.With(buffer.ExtendHeader(c.frontHeadroom(addrLen)))
		common.Must(
			binary.Write(header, binary.BigEndian, uint16(5+addrLen)),
			header.WriteByte(0),
			header.WriteByte(0),
			header.WriteByte(1), // frame type new
			header.WriteByte(1), // option data
			header.WriteByte(NetworkUDP),
		)
		err := AddressSerializer.WriteAddrPort(header, destination)
		if err != nil {
			buffer.Release()
			return err
		}
		common.Must(binary.Write(header, binary.BigEndian, uint16(dataLen)))
		c.requestWritten = true
	} else {
		header := buffer.ExtendHeader(c.frontHeadroom(addrLen))
		binary.BigEndian.PutUint16(header, uint16(5+addrLen))
		header[2] = 0
		header[3] = 0
		header[4] = 2 // frame keep
		header[5] = 1 // option data
		header[6] = NetworkUDP
		err := AddressSerializer.WriteAddrPort(buf.With(header[7:]), destination)
		if err != nil {
			buffer.Release()
			return err
		}
		binary.BigEndian.PutUint16(header[7+addrLen:], uint16(dataLen))
	}
	return c.writer.WriteBuffer(buffer)
}

func (c *XUDPConn) FrontHeadroom() int {
	return c.frontHeadroom(M.MaxSocksaddrLength)
}

func (c *XUDPConn) NeedHandshakeForWrite() bool {
	return !c.requestWritten
}

func (c *XUDPConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *XUDPConn) Upstream() any {
	return c.Conn
}

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

type MuxConnWrapper struct {
	net.Conn
	writer         N.ExtendedWriter
	destination    M.Socksaddr
	requestWritten bool
	remaining      int
}

func NewMuxConnWrapper(conn net.Conn, destination M.Socksaddr) *MuxConnWrapper {
	return &MuxConnWrapper{
		Conn:        conn,
		writer:      bufio.NewExtendedWriter(conn),
		destination: destination,
	}
}

func (c *MuxConnWrapper) Read(p []byte) (n int, err error) {
	for c.remaining == 0 {
		var header [6]byte
		_, err = io.ReadFull(c.Conn, header[:])
		if err != nil {
			return
		}
		length := binary.BigEndian.Uint16(header[:2])
		status := header[4]
		option := header[5]
		switch status {
		case StatusNew:
			return 0, E.New("unexpected frame new")
		case StatusKeep, StatusKeepAlive:
		case StatusEnd:
			return 0, io.EOF
		default:
			return 0, E.New("unexpected frame: ", status)
		}
		if length > 4 {
			_, err = io.CopyN(io.Discard, c.Conn, int64(length-4))
			if err != nil {
				return
			}
		}
		if option&OptionError == OptionError {
			return 0, E.Cause(net.ErrClosed, "remote closed")
		}
		if option&OptionData == OptionData {
			_, err = io.ReadFull(c.Conn, header[:2])
			if err != nil {
				return
			}
			c.remaining = int(binary.BigEndian.Uint16(header[:2]))
		}
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err = c.Conn.Read(p)
	c.remaining -= n
	return
}

func (c *MuxConnWrapper) Write(p []byte) (n int, err error) {
	return bufio.WriteBuffer(c, buf.As(p))
}

func (c *MuxConnWrapper) WriteBuffer(buffer *buf.Buffer) error {
	dataLen := buffer.Len()
	addrLen := M.SocksaddrSerializer.AddrPortLen(c.destination)
	if !c.requestWritten {
		header := buf.With(buffer.ExtendHeader(c.frontHeadroom(addrLen)))
		common.Must(
			binary.Write(header, binary.BigEndian, uint16(5+addrLen)),
			header.WriteByte(0),
			header.WriteByte(0),
			header.WriteByte(1), // frame type new
			header.WriteByte(1), // option data
			header.WriteByte(NetworkTCP),
		)
		err := AddressSerializer.WriteAddrPort(header, c.destination)
		if err != nil {
			buffer.Release()
			return err
		}
		common.Must(binary.Write(header, binary.BigEndian, uint16(dataLen)))
		c.requestWritten = true
	} else {
		header := buffer.ExtendHeader(c.frontHeadroom(addrLen))
		binary.BigEndian.PutUint16(header, 4)
		header[2] = 0
		header[3] = 0
		header[4] = 2 // frame keep
		header[5] = 1 // option data
		binary.BigEndian.PutUint16(header[6:], uint16(dataLen))
	}
	return c.writer.WriteBuffer(buffer)
}

func (c *MuxConnWrapper) frontHeadroom(addrLen int) int {
	if !c.requestWritten {
		var headerLen int
		headerLen += 2 // frame len
		headerLen += 5 // frame header
		headerLen += addrLen
		headerLen += 2 // payload len
		return headerLen
	} else {
		return 8
	}
}

func (c *MuxConnWrapper) FrontHeadroom() int {
	return c.frontHeadroom(M.MaxSocksaddrLength)
}

func (c *MuxConnWrapper) Upstream() any {
	return c.Conn
}

var (
	_ N.ExtendedWriter = (*MuxConnWrapper)(nil)
	_ N.FrontHeadroom  = (*MuxConnWrapper)(nil)
)

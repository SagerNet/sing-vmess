package vmess

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func HandleMuxConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, handler Handler) error {
	ctx, cancel := context.WithCancelCause(ctx)
	session := &serverSession{
		ctx:           ctx,
		source:        source,
		conn:          conn,
		writer:        bufio.NewExtendedWriter(conn),
		frontHeadroom: N.CalculateFrontHeadroom(conn),
		rearHeadroom:  N.CalculateRearHeadroom(conn),
		handler:       handler,
		streams:       make(map[uint16]*serverStream),
	}
	go func() {
		<-ctx.Done()
		session.cleanup(ctx.Err())
	}()
	return session.recvLoop(cancel)
}

type serverSession struct {
	ctx           context.Context
	source        M.Socksaddr
	conn          net.Conn
	writer        N.ExtendedWriter
	writeAccess   sync.Mutex
	frontHeadroom int
	rearHeadroom  int
	handler       Handler
	streamAccess  sync.RWMutex
	streams       map[uint16]*serverStream
}

type serverStream struct {
	network     byte
	destination M.Socksaddr
	pipe        *io.PipeWriter
}

func (c *serverSession) recvLoop(cancel context.CancelCauseFunc) error {
	for {
		err := c.recv()
		if err != nil {
			cancel(err)
			return E.Cause(err, "mux connection closed")
		}
	}
}

func (c *serverSession) cleanup(err error) {
	c.streamAccess.Lock()
	for _, stream := range c.streams {
		_ = stream.pipe.CloseWithError(err)
	}
	c.streamAccess.Unlock()
}

func (c *serverSession) recv() error {
	var length uint16
	err := binary.Read(c.conn, binary.BigEndian, &length)
	if err != nil {
		return E.Cause(err, "read frame header")
	}

	var sessionID uint16
	err = binary.Read(c.conn, binary.BigEndian, &sessionID)
	if err != nil {
		return err
	}

	var status byte
	err = binary.Read(c.conn, binary.BigEndian, &status)
	if err != nil {
		return err
	}

	var option byte
	err = binary.Read(c.conn, binary.BigEndian, &option)
	if err != nil {
		return err
	}

	var network byte
	var destination M.Socksaddr
	if length > 4 {
		limitReader := io.LimitReader(c.conn, int64(length-4))
		err = binary.Read(limitReader, binary.BigEndian, &network)
		if err != nil {
			return err
		}
		destination, err = AddressSerializer.ReadAddrPort(limitReader)
		if err != nil {
			return err
		}
		if limitReader.(*io.LimitedReader).N > 0 {
			_, err = io.Copy(io.Discard, limitReader)
			if err != nil {
				return err
			}
		}
	}

	var stream *serverStream
	switch status {
	case StatusNew:
		pipeIn, pipeOut := io.Pipe()
		stream = &serverStream{
			network,
			destination,
			pipeOut,
		}
		c.streamAccess.Lock()
		c.streams[sessionID] = stream
		c.streamAccess.Unlock()
		switch network {
		case NetworkTCP, NetworkUDP:
		default:
			return E.New("bad network: ", network)
		}
		go func() {
			if network == NetworkTCP {
				conn := &serverMuxConn{
					sessionID,
					pipeIn,
					c,
				}
				c.handler.NewConnectionEx(c.ctx, conn, c.source, destination, nil)
			} else {
				conn := &serverMuxPacketConn{
					sessionID,
					pipeIn,
					c,
					destination,
				}
				c.handler.NewPacketConnectionEx(c.ctx, conn, c.source, destination, nil)
			}
		}()
	case StatusKeep:
		var loaded bool
		c.streamAccess.Lock()
		stream, loaded = c.streams[sessionID]
		c.streamAccess.Unlock()
		if !loaded {
			go c.syncClose(sessionID, true)
		}
	case StatusEnd:
		if option&OptionError == OptionError {
			err = E.New("remote closed wth error")
		}
		c.localClose(sessionID, err)
	case StatusKeepAlive:
	default:
		return E.New("bad session status: ", status)
	}

	if option&OptionData != OptionData {
		return nil
	}

	err = binary.Read(c.conn, binary.BigEndian, &length)
	if err != nil {
		return err
	}

	if length == 0 {
		return nil
	}

	if stream == nil {
		return common.Error(io.CopyN(io.Discard, c.conn, int64(length)))
	}

	data := buf.NewSize(int(length))
	defer data.Release()

	_, err = data.ReadFullFrom(c.conn, int(length))
	if err != nil {
		return err
	}

	if !destination.IsValid() {
		destination = stream.destination
	}

	err = c.recvTo(stream, data, destination)
	if err != nil && c.localClose(sessionID, err) {
		go c.syncClose(sessionID, true)
	}
	return nil
}

func (c *serverSession) recvTo(stream *serverStream, data *buf.Buffer, destination M.Socksaddr) error {
	if stream.network == NetworkTCP {
		return common.Error(stream.pipe.Write(data.Bytes()))
	} else {
		err := binary.Write(stream.pipe, binary.BigEndian, uint16(data.Len()))
		if err != nil {
			return err
		}
		_, err = stream.pipe.Write(data.Bytes())
		if err != nil {
			return err
		}
		err = AddressSerializer.WriteAddrPort(stream.pipe, destination)
		if err != nil {
			return err
		}
		return nil
	}
}

func (c *serverSession) writeBuffer(buffer *buf.Buffer) error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return c.writer.WriteBuffer(buffer)
}

func (c *serverSession) close(sessionID uint16) error {
	if c.localClose(sessionID, nil) {
		return c.syncClose(sessionID, false)
	}
	return nil
}

func (c *serverSession) localClose(sessionID uint16, err error) bool {
	var closed bool
	c.streamAccess.Lock()
	if session, loaded := c.streams[sessionID]; loaded {
		delete(c.streams, sessionID)
		_ = session.pipe.CloseWithError(err)
		closed = true
	}
	c.streamAccess.Unlock()
	return closed
}

func (c *serverSession) syncClose(sessionID uint16, hasError bool) error {
	var option byte
	if hasError {
		option = OptionError
	}
	buffer := buf.NewSize(c.frontHeadroom + 6 + c.rearHeadroom)
	buffer.Resize(c.frontHeadroom, 0)
	frame := buffer.Extend(6)
	binary.BigEndian.PutUint16(frame, 4)
	binary.BigEndian.PutUint16(frame[2:], sessionID)
	frame[4] = StatusEnd
	frame[5] = option
	return c.writeBuffer(buffer)
}

type serverMuxConn struct {
	sessionID uint16
	pipe      *io.PipeReader
	session   *serverSession
}

func (c *serverMuxConn) Read(b []byte) (n int, err error) {
	return c.pipe.Read(b)
}

func (c *serverMuxConn) Write(b []byte) (n int, err error) {
	return bufio.WriteBuffer(c, buf.As(b))
}

func (c *serverMuxConn) WriteBuffer(buffer *buf.Buffer) error {
	dataLen := buffer.Len()
	header := buf.With(buffer.ExtendHeader(8))
	common.Must(
		binary.Write(header, binary.BigEndian, uint16(4)),
		binary.Write(header, binary.BigEndian, c.sessionID),
		binary.Write(header, binary.BigEndian, uint8(StatusKeep)),
		binary.Write(header, binary.BigEndian, uint8(OptionData)),
		binary.Write(header, binary.BigEndian, uint16(dataLen)),
	)
	return c.session.writeBuffer(buffer)
}

func (c *serverMuxConn) FrontHeadroom() int {
	return 8 + c.session.frontHeadroom
}

func (c *serverMuxConn) RearHeadroom() int {
	return c.session.rearHeadroom
}

func (c *serverMuxConn) Close() error {
	return c.session.close(c.sessionID)
}

func (c *serverMuxConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) NeedAdditionalReadDeadline() bool {
	return true
}

var _ PacketConn = (*serverMuxPacketConn)(nil)

type serverMuxPacketConn struct {
	sessionID   uint16
	pipe        *io.PipeReader
	session     *serverSession
	destination M.Socksaddr
}

func (c *serverMuxPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *serverMuxPacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.destination)
}

func (c *serverMuxPacketConn) RemoteAddr() net.Addr {
	return c.destination.UDPAddr()
}

func (c *serverMuxPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var length uint16
	err = binary.Read(c.pipe, binary.BigEndian, &length)
	if err != nil {
		return
	}
	if int(length) > len(p) {
		return 0, nil, E.Extend(io.ErrShortBuffer, "mux need ", length)
	}
	n, err = io.ReadFull(c.pipe, p[:length])
	if err == nil {
		addr, err = AddressSerializer.ReadAddrPort(c.pipe)
	}
	return
}

func (c *serverMuxPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	var length uint16
	err = binary.Read(c.pipe, binary.BigEndian, &length)
	if err != nil {
		return
	}
	if int(length) > buffer.FreeLen() {
		return M.Socksaddr{}, E.Extend(io.ErrShortBuffer, "mux need ", length)
	}
	_, err = buffer.ReadFullFrom(c.pipe, int(length))
	if err == nil {
		destination, err = AddressSerializer.ReadAddrPort(c.pipe)
		if err == nil {
			destination = destination.Unwrap()
		}
	}
	return
}

func (c *serverMuxPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return bufio.WritePacketBuffer(c, buf.As(p), M.SocksaddrFromNet(addr))
}

func (c *serverMuxPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	dataLen := buffer.Len()
	header := buf.With(buffer.ExtendHeader(9 + AddressSerializer.AddrPortLen(destination)))
	common.Must(
		binary.Write(header, binary.BigEndian, uint16(5+AddressSerializer.AddrPortLen(destination))),
		binary.Write(header, binary.BigEndian, c.sessionID),
		binary.Write(header, binary.BigEndian, uint8(StatusKeep)),
		binary.Write(header, binary.BigEndian, uint8(OptionData)),
		binary.Write(header, binary.BigEndian, uint8(NetworkUDP)),
	)
	err := AddressSerializer.WriteAddrPort(header, destination)
	if err != nil {
		buffer.Release()
		return err
	}
	common.Must(binary.Write(header, binary.BigEndian, uint16(dataLen)))
	return c.session.writeBuffer(buffer)
}

func (c *serverMuxPacketConn) FrontHeadroom() int {
	return 9 + M.MaxSocksaddrLength + c.session.frontHeadroom
}

func (c *serverMuxPacketConn) RearHeadroom() int {
	return c.session.rearHeadroom
}

func (c *serverMuxPacketConn) Close() error {
	return c.session.close(c.sessionID)
}

func (c *serverMuxPacketConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxPacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

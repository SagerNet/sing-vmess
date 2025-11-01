package vless

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

var tlsRegistry []func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr)

func init() {
	tlsRegistry = append(tlsRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr) {
		tlsConn, loaded := N.CastReader[*tls.Conn](conn)
		if !loaded {
			return
		}
		return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn).Elem(), uintptr(unsafe.Pointer(tlsConn))
	})
}

const xrayChunkSize = 8192

type VisionConn struct {
	net.Conn
	reader      *bufio.ChunkReader
	writer      N.VectorisedWriter
	writeAccess sync.Mutex
	input       *bytes.Reader
	rawInput    *bytes.Buffer
	netConn     net.Conn
	rawConn     net.Conn // raw connection for direct mode (may include encryption layer)
	logger      logger.Logger

	userUUID               [16]byte
	isTLS                  bool
	numberOfPacketToFilter int
	isTLS12orAbove         bool
	remainingServerHello   int32
	cipher                 uint16
	enableXTLS             bool
	isPadding              bool
	directWrite            bool
	writeUUID              bool
	withinPaddingBuffers   bool
	remainingContent       int
	remainingPadding       int
	currentCommand         byte
	directRead             bool
	remainingBuffers       []*buf.Buffer
}

func NewVisionConn(conn net.Conn, tlsConn net.Conn, userUUID [16]byte, logger logger.Logger) (*VisionConn, error) {
	// tlsConn can be:
	// 1. TLS connection (when TLS/Reality is used)
	// 2. Encryption layer (when only encryption is used, no TLS/Reality)
	// Unwrap to find the actual connection
	originalTLSConn := unwrapConn(tlsConn)

	var (
		loaded         bool
		reflectType    reflect.Type
		reflectPointer uintptr
		netConn        net.Conn
		input          *bytes.Reader
		rawInput       *bytes.Buffer
		rawConn        net.Conn
	)

	// Check if originalTLSConn is an encryption layer (no TLS/Reality case)
	isEncryptionOnly := false
	var actualConn net.Conn // Declare here to avoid goto issue
	var hasEncryption bool  // Declare here to avoid goto issue

	if upstream, ok := originalTLSConn.(common.WithUpstream); ok {
		if upstreamConn, ok := upstream.Upstream().(net.Conn); ok {
			// This is an encryption layer
			connType := reflect.TypeOf(originalTLSConn).Elem()
			if connType.Name() == "CommonConn" || connType.Name() == "XorConn" {
				isEncryptionOnly = true
				// For encryption-only mode, use the encryption layer's upstream as netConn
				netConn = upstreamConn

				// Directly use encryption layer's input/rawInput fields
				if connType.Name() == "CommonConn" {
					reflectType = connType
					reflectPointer = uintptr(unsafe.Pointer(reflect.ValueOf(originalTLSConn).Pointer()))

					inputField, inputOk := reflectType.FieldByName("input")
					rawInputField, rawInputOk := reflectType.FieldByName("rawInput")

					if inputOk && rawInputOk {
						input = (*bytes.Reader)(unsafe.Pointer(reflectPointer + inputField.Offset))
						rawInput = (*bytes.Buffer)(unsafe.Pointer(reflectPointer + rawInputField.Offset))
						// In encryption-only mode, rawConn should be the upstream of encryption layer
						// This allows Vision to bypass encryption in direct mode
						rawConn = upstreamConn

						// Skip the rest of the unwrapping logic
						goto skipUnwrap
					}
				}
			}
		}
	}

	// Check if conn has encryption layer
	// If so, use encryption layer's input/rawInput fields
	hasEncryption = false

	// The conn passed in is vless.Conn which wraps the actual connection stack
	// We need to unwrap to find the encryption layer (CommonConn)
	actualConn = conn

	// First, check if this is a visionConnWrapper
	if wrapper, ok := conn.(common.WithUpstream); ok {
		if _, ok := wrapper.Upstream().(net.Conn); ok {
			// The wrapper's embedded Conn field is what we want
			wrapperValue := reflect.ValueOf(conn).Elem()
			connField := wrapperValue.FieldByName("Conn")
			if connField.IsValid() {
				actualConn = connField.Interface().(net.Conn)
			}
		}
	}

	// Now actualConn might be vless.Conn, which embeds ExtendedConn
	// We need to unwrap further to find the encryption layer
	// Try to access ExtendedConn field
	if actualConnValue := reflect.ValueOf(actualConn); actualConnValue.Kind() == reflect.Ptr {
		actualConnElem := actualConnValue.Elem()
		if extendedConnField := actualConnElem.FieldByName("ExtendedConn"); extendedConnField.IsValid() {
			extendedConn := extendedConnField.Interface()

			// ExtendedConn might wrap the encryption layer
			// Try to unwrap it by calling Upstream() if available
			if extendedWithUpstream, ok := extendedConn.(common.WithUpstream); ok {
				if upstream := extendedWithUpstream.Upstream(); upstream != nil {
					if upstreamConn, ok := upstream.(net.Conn); ok {
						actualConn = upstreamConn
					}
				}
			}
		}
	}

	// Now check if actualConn is visionConnWrapper again (nested wrapping)
	// If so, unwrap it to get the encryption layer
	if wrapper, ok := actualConn.(common.WithUpstream); ok {
		if _, ok := wrapper.Upstream().(net.Conn); ok {
			// Access the Conn field to get the encryption layer
			wrapperValue := reflect.ValueOf(actualConn).Elem()
			connField := wrapperValue.FieldByName("Conn")
			if connField.IsValid() {
				actualConn = connField.Interface().(net.Conn)
			}
		}
	}

	// Now check if actualConn is an encryption layer (CommonConn or XorConn)
	if upstream, ok := actualConn.(common.WithUpstream); ok {
		if upstreamConn, ok := upstream.Upstream().(net.Conn); ok {
			// Check if this is XorConn - if so, don't penetrate it
			actualConnType := reflect.TypeOf(actualConn).Elem()
			if actualConnType.Name() == "XorConn" {
				// XorConn should not be penetrated in direct mode
				// Use XorConn itself as rawConn
				hasEncryption = true
				rawConn = actualConn

				// XorConn doesn't have input/rawInput fields, use TLS connection's fields
				for _, tlsCreator := range tlsRegistry {
					var tlsReflectType reflect.Type
					var tlsReflectPointer uintptr
					loaded, _, tlsReflectType, tlsReflectPointer = tlsCreator(originalTLSConn)
					if loaded {
						inputField, _ := tlsReflectType.FieldByName("input")
						rawInputField, _ := tlsReflectType.FieldByName("rawInput")
						input = (*bytes.Reader)(unsafe.Pointer(tlsReflectPointer + inputField.Offset))
						rawInput = (*bytes.Buffer)(unsafe.Pointer(tlsReflectPointer + rawInputField.Offset))
						break
					}
				}
			} else {
				// This is CommonConn - use reflection to access its input/rawInput fields
				hasEncryption = true
				reflectType = reflect.TypeOf(actualConn).Elem()
				reflectPointer = uintptr(unsafe.Pointer(reflect.ValueOf(actualConn).Pointer()))

				inputField, inputOk := reflectType.FieldByName("input")
				rawInputField, rawInputOk := reflectType.FieldByName("rawInput")

				if inputOk && rawInputOk {
					input = (*bytes.Reader)(unsafe.Pointer(reflectPointer + inputField.Offset))
					rawInput = (*bytes.Buffer)(unsafe.Pointer(reflectPointer + rawInputField.Offset))
				} else {
					return nil, E.New("vision: encryption layer missing input/rawInput fields")
				}

				// For rawConn in direct mode
				if isEncryptionOnly {
					// Encryption-only mode: use encryption layer itself
					rawConn = actualConn
				} else {
					// TLS + Encryption mode: use the encryption layer's upstream (TLS connection)
					rawConn = upstreamConn
				}
			}
		}
	}

	// Get TLS connection info for netConn (only if not encryption-only mode)
	if !isEncryptionOnly {
		for _, tlsCreator := range tlsRegistry {
			loaded, netConn, _, _ = tlsCreator(originalTLSConn)
			if loaded {
				break
			}
		}
		if !loaded {
			return nil, E.New("vision: not a valid supported TLS connection: ", reflect.TypeOf(originalTLSConn))
		}
	}

	// If no encryption layer, use TLS connection's input/rawInput fields
	// Or if encryption-only mode, use encryption layer's fields
	if !hasEncryption {
		if isEncryptionOnly {
			// Encryption-only mode: use encryption layer's input/rawInput
			reflectType = reflect.TypeOf(originalTLSConn).Elem()
			reflectPointer = uintptr(unsafe.Pointer(reflect.ValueOf(originalTLSConn).Pointer()))

			inputField, inputOk := reflectType.FieldByName("input")
			rawInputField, rawInputOk := reflectType.FieldByName("rawInput")

			if inputOk && rawInputOk {
				input = (*bytes.Reader)(unsafe.Pointer(reflectPointer + inputField.Offset))
				rawInput = (*bytes.Buffer)(unsafe.Pointer(reflectPointer + rawInputField.Offset))
			} else {
				return nil, E.New("vision: encryption layer missing input/rawInput fields")
			}
		} else {
			// TLS mode: use TLS connection's input/rawInput
			for _, tlsCreator := range tlsRegistry {
				loaded, netConn, reflectType, reflectPointer = tlsCreator(originalTLSConn)
				if loaded {
					break
				}
			}
			inputField, _ := reflectType.FieldByName("input")
			rawInputField, _ := reflectType.FieldByName("rawInput")
			input = (*bytes.Reader)(unsafe.Pointer(reflectPointer + inputField.Offset))
			rawInput = (*bytes.Buffer)(unsafe.Pointer(reflectPointer + rawInputField.Offset))
		}
	}

	// Determine rawConn for direct mode if not already set by encryption detection
	if rawConn == nil {
		if isEncryptionOnly {
			// Encryption-only mode: use encryption layer for direct mode
			// This allows Vision to work with encryption without TLS
			rawConn = originalTLSConn
		} else {
			// Without encryption: use TCP connection for direct mode
			rawConn = netConn
		}
	}

skipUnwrap:
	return &VisionConn{
		Conn:     conn,
		reader:   bufio.NewChunkReader(conn, xrayChunkSize),
		writer:   bufio.NewVectorisedWriter(conn),
		input:    input,
		rawInput: rawInput,
		netConn:  netConn,
		rawConn:  rawConn,
		logger:   logger,

		userUUID:               userUUID,
		numberOfPacketToFilter: 8,
		remainingServerHello:   -1,
		isPadding:              true,
		writeUUID:              true,
		withinPaddingBuffers:   true,
		remainingContent:       -1,
		remainingPadding:       -1,
	}, nil
}

type netConnProvider interface {
	NetConn() net.Conn
}

func unwrapConn(conn net.Conn) net.Conn {
	visited := make(map[net.Conn]struct{})
	for conn != nil {
		if _, ok := visited[conn]; ok {
			break
		}
		visited[conn] = struct{}{}

		// Check if this is a TLS connection by testing with TLS registry
		if isTLSConn(conn) {
			break
		}

		// Check if this is an encryption layer (CommonConn/XorConn) - stop here
		if reflect.TypeOf(conn).Kind() == reflect.Ptr {
			typeName := reflect.TypeOf(conn).Elem().Name()
			if typeName == "CommonConn" || typeName == "XorConn" {
				// Stop unwrapping at encryption layer
				break
			}
		}

		switched := false

		// Try common.WithUpstream first (most specific)
		if upstream, ok := conn.(common.WithUpstream); ok {
			if next, ok := upstream.Upstream().(net.Conn); ok && next != nil && next != conn {
				conn = next
				switched = true
				continue
			}
		}

		// Then try netConnProvider
		if provider, ok := conn.(netConnProvider); ok {
			next := provider.NetConn()
			if next != nil && next != conn {
				conn = next
				switched = true
				continue
			}
		}

		if reader, ok := conn.(N.WithUpstreamReader); ok {
			if replacer, ok := conn.(N.ReaderWithUpstream); ok && replacer.ReaderReplaceable() {
				if next, ok := reader.UpstreamReader().(net.Conn); ok && next != nil && next != conn {
					conn = next
					switched = true
					continue
				}
			}
		}
		if writer, ok := conn.(N.WithUpstreamWriter); ok {
			if replacer, ok := conn.(N.WriterWithUpstream); ok && replacer.WriterReplaceable() {
				if next, ok := writer.UpstreamWriter().(net.Conn); ok && next != nil && next != conn {
					conn = next
					switched = true
					continue
				}
			}
		}
		if !switched {
			break
		}
	}
	return conn
}

// isTLSConn checks if a connection can be recognized by the TLS registry
func isTLSConn(conn net.Conn) bool {
	for _, tlsCreator := range tlsRegistry {
		loaded, _, _, _ := tlsCreator(conn)
		if loaded {
			return true
		}
	}
	return false
}

func (c *VisionConn) Read(p []byte) (n int, err error) {
	for len(c.remainingBuffers) > 0 {
		newN, _ := c.remainingBuffers[0].Read(p[n:])
		if c.remainingBuffers[0].IsEmpty() {
			c.remainingBuffers[0].Release()
			c.remainingBuffers = c.remainingBuffers[1:]
		}
		n += newN
		if n == len(p) {
			break
		}
	}
	if n > 0 {
		return
	}
	if c.directRead {
		return c.rawConn.Read(p)
	}
	var bufferBytes []byte
	var chunkBuffer *buf.Buffer
	if len(p) > xrayChunkSize {
		n, err = c.Conn.Read(p)
		if err != nil {
			return
		}
		bufferBytes = p[:n]
	} else {
		chunkBuffer, err = c.reader.ReadChunk()
		if err != nil {
			return 0, err
		}
		bufferBytes = chunkBuffer.Bytes()
	}
	if c.withinPaddingBuffers || c.numberOfPacketToFilter > 0 {
		buffers := c.unPadding(bufferBytes)
		if chunkBuffer != nil {
			chunkBuffer.Reset()
		}
		if c.remainingContent == 0 && c.remainingPadding == 0 {
			if c.currentCommand == commandPaddingEnd {
				c.withinPaddingBuffers = false
				c.remainingContent = -1
				c.remainingPadding = -1
			} else if c.currentCommand == commandPaddingDirect {
				c.withinPaddingBuffers = false
				c.directRead = true

				inputBuffer, err := io.ReadAll(c.input)
				if err != nil {
					return 0, err
				}
				buffers = append(buffers, buf.As(inputBuffer))

				rawInputBuffer, err := io.ReadAll(c.rawInput)
				if err != nil {
					return 0, err
				}

				buffers = append(buffers, buf.As(rawInputBuffer))

				c.logger.Trace("XtlsRead readV")
			} else if c.currentCommand == commandPaddingContinue {
				c.withinPaddingBuffers = true
			} else {
				return 0, E.New("unknown command ", c.currentCommand)
			}
		} else if c.remainingContent > 0 || c.remainingPadding > 0 {
			c.withinPaddingBuffers = true
		} else {
			c.withinPaddingBuffers = false
		}
		if c.numberOfPacketToFilter > 0 {
			c.filterTLS(buf.ToSliceMulti(buffers))
		}
		c.remainingBuffers = buffers
		return c.Read(p)
	} else {
		if c.numberOfPacketToFilter > 0 {
			c.filterTLS([][]byte{bufferBytes})
		}
		if chunkBuffer != nil {
			c.remainingBuffers = append(c.remainingBuffers, buf.As(chunkBuffer.Bytes()))
			chunkBuffer.Reset() // chunkBuffer should not be release and only reused after c.remainingBuffers be emptied, so must reset at here
			return c.Read(p)
		}
		return
	}
}

func (c *VisionConn) Write(p []byte) (n int, err error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if c.numberOfPacketToFilter > 0 {
		c.filterTLS([][]byte{p})
	}
	if c.isPadding {
		inputLen := len(p)
		buffers := reshapeBuffer(p)
		var specIndex int
		for i, buffer := range buffers {
			if c.isTLS && buffer.Len() > 6 && bytes.Equal(tlsApplicationDataStart, buffer.To(3)) {
				var command byte = commandPaddingEnd
				if c.enableXTLS {
					c.directWrite = true
					specIndex = i
					command = commandPaddingDirect
				}
				c.isPadding = false
				buffers[i] = c.padding(buffer, command)
				break
			} else if !c.isTLS12orAbove && c.numberOfPacketToFilter <= 1 {
				c.isPadding = false
				buffers[i] = c.padding(buffer, commandPaddingEnd)
				break
			}
			buffers[i] = c.padding(buffer, commandPaddingContinue)
		}
		if c.directWrite {
			encryptedBuffer := buffers[:specIndex+1]
			err = c.writer.WriteVectorised(encryptedBuffer)
			if err != nil {
				return
			}
			buffers = buffers[specIndex+1:]
			c.writer = bufio.NewVectorisedWriter(c.rawConn)
			if len(buffers) > 0 {
				c.logger.Trace("XtlsWrite writeV ", specIndex, " ", buf.LenMulti(encryptedBuffer), " ", len(buffers))
				time.Sleep(5 * time.Millisecond) // wtf
			}
		}
		if len(buffers) > 0 {
			err = c.writer.WriteVectorised(buffers)
		}
		if err == nil {
			n = inputLen
		}
		return
	}
	if c.directWrite {
		return c.rawConn.Write(p)
	} else {
		return c.Conn.Write(p)
	}
}

func (c *VisionConn) filterTLS(buffers [][]byte) {
	for _, buffer := range buffers {
		c.numberOfPacketToFilter--
		if len(buffer) > 6 {
			if buffer[0] == 22 && buffer[1] == 3 && buffer[2] == 3 {
				c.isTLS = true
				if buffer[5] == 2 {
					c.isTLS12orAbove = true
					c.remainingServerHello = (int32(buffer[3])<<8 | int32(buffer[4])) + 5
					if len(buffer) >= 79 && c.remainingServerHello >= 79 {
						sessionIdLen := int32(buffer[43])
						cipherSuite := buffer[43+sessionIdLen+1 : 43+sessionIdLen+3]
						c.cipher = uint16(cipherSuite[0])<<8 | uint16(cipherSuite[1])
					} else {
						c.logger.Trace("XtlsFilterTls short server hello, tls 1.2 or older? ", len(buffer), " ", c.remainingServerHello)
					}
				}
			} else if bytes.Equal(tlsClientHandShakeStart, buffer[:2]) && buffer[5] == 1 {
				c.isTLS = true
				c.logger.Trace("XtlsFilterTls found tls client hello! ", len(buffer))
			}
		}
		if c.remainingServerHello > 0 {
			end := int(c.remainingServerHello)
			if end > len(buffer) {
				end = len(buffer)
			}
			c.remainingServerHello -= int32(end)
			if bytes.Contains(buffer[:end], tls13SupportedVersions) {
				cipher, ok := tls13CipherSuiteDic[c.cipher]
				if ok && cipher != "TLS_AES_128_CCM_8_SHA256" {
					c.enableXTLS = true
				}
				c.logger.Trace("XtlsFilterTls found tls 1.3! ", len(buffer), " ", c.cipher, " ", c.enableXTLS)
				c.numberOfPacketToFilter = 0
				return
			} else if c.remainingServerHello == 0 {
				c.logger.Trace("XtlsFilterTls found tls 1.2! ", len(buffer))
				c.numberOfPacketToFilter = 0
				return
			}
		}
		if c.numberOfPacketToFilter == 0 {
			c.logger.Trace("XtlsFilterTls stop filtering ", len(buffer))
		}
	}
}

func (c *VisionConn) padding(buffer *buf.Buffer, command byte) *buf.Buffer {
	contentLen := 0
	paddingLen := 0
	if buffer != nil {
		contentLen = buffer.Len()
	}
	if contentLen < 900 && c.isTLS {
		l, _ := rand.Int(rand.Reader, big.NewInt(500))
		paddingLen = int(l.Int64()) + 900 - contentLen
	} else {
		l, _ := rand.Int(rand.Reader, big.NewInt(256))
		paddingLen = int(l.Int64())
	}
	var bufferLen int
	if c.writeUUID {
		bufferLen += 16
	}
	bufferLen += 5
	if buffer != nil {
		bufferLen += buffer.Len()
	}
	bufferLen += paddingLen
	newBuffer := buf.NewSize(bufferLen)
	if c.writeUUID {
		common.Must1(newBuffer.Write(c.userUUID[:]))
		c.writeUUID = false
	}
	common.Must1(newBuffer.Write([]byte{command, byte(contentLen >> 8), byte(contentLen), byte(paddingLen >> 8), byte(paddingLen)}))
	if buffer != nil {
		common.Must1(newBuffer.Write(buffer.Bytes()))
		buffer.Release()
	}
	newBuffer.Extend(paddingLen)
	c.logger.Trace("XtlsPadding ", contentLen, " ", paddingLen, " ", command)
	return newBuffer
}

func (c *VisionConn) unPadding(buffer []byte) []*buf.Buffer {
	var bufferIndex int
	if c.remainingContent == -1 && c.remainingPadding == -1 {
		if len(buffer) >= 21 && bytes.Equal(c.userUUID[:], buffer[:16]) {
			bufferIndex = 16
			c.remainingContent = 0
			c.remainingPadding = 0
			c.currentCommand = 0
		}
	}
	if c.remainingContent == -1 && c.remainingPadding == -1 {
		return []*buf.Buffer{buf.As(buffer).ToOwned()}
	}
	var buffers []*buf.Buffer
	for bufferIndex < len(buffer) {
		if c.remainingContent <= 0 && c.remainingPadding <= 0 {
			if c.currentCommand == 1 {
				buffers = append(buffers, buf.As(buffer[bufferIndex:]).ToOwned())
				break
			} else {
				paddingInfo := buffer[bufferIndex : bufferIndex+5]
				c.currentCommand = paddingInfo[0]
				c.remainingContent = int(paddingInfo[1])<<8 | int(paddingInfo[2])
				c.remainingPadding = int(paddingInfo[3])<<8 | int(paddingInfo[4])
				bufferIndex += 5
				c.logger.Trace("Xtls Unpadding new block ", bufferIndex, " ", c.remainingContent, " padding ", c.remainingPadding, " ", c.currentCommand)
			}
		} else if c.remainingContent > 0 {
			end := c.remainingContent
			if end > len(buffer)-bufferIndex {
				end = len(buffer) - bufferIndex
			}
			buffers = append(buffers, buf.As(buffer[bufferIndex:bufferIndex+end]).ToOwned())
			c.remainingContent -= end
			bufferIndex += end
		} else {
			end := c.remainingPadding
			if end > len(buffer)-bufferIndex {
				end = len(buffer) - bufferIndex
			}
			c.remainingPadding -= end
			bufferIndex += end
		}
		if bufferIndex == len(buffer) {
			break
		}
	}
	return buffers
}

func (c *VisionConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *VisionConn) Upstream() any {
	return c.Conn
}

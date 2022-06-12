package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash/fnv"
	"io"
	mRand "math/rand"
	"net"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	vmessaead "github.com/v2fly/v2ray-core/v5/proxy/vmess/aead"
)

type Client struct {
	key                 []byte
	security            byte
	globalPadding       bool
	authenticatedLength bool
}

func (c *Client) NeedBuffer() bool {
	switch c.security {
	case SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305:
		return true
	default:
		return false
	}
}

type clientConn struct {
	*Client
	upstream    net.Conn
	command     byte
	security    byte
	option      byte
	destination M.Socksaddr

	requestKey   [16]byte
	requestNonce [16]byte
	reader       io.Reader
	readBuffer   *buf.Buffer
	writer       io.Writer
}

func (c *Client) dialClient(upstream net.Conn, command byte, destination M.Socksaddr, readBuffer *buf.Buffer) *clientConn {
	var conn clientConn
	conn.Client = c
	conn.upstream = upstream
	conn.command = command
	conn.destination = destination
	common.Must1(io.ReadFull(rand.Reader, conn.requestKey[:]))
	common.Must1(io.ReadFull(rand.Reader, conn.requestNonce[:]))

	security := c.security
	var option byte

	if security != SecurityTypeNone {
		conn.readBuffer = readBuffer
	} else {
		readBuffer.Release()
	}

	switch security {
	case SecurityTypeNone:
		if command == CommandUDP {
			option = RequestOptionChunkStream
		}
	case SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305:
		option = RequestOptionChunkStream
		if c.globalPadding {
			option |= RequestOptionGlobalPadding
		}
		if c.authenticatedLength {
			option |= RequestOptionAuthenticatedLength
		} else {
			option |= RequestOptionChunkMasking
		}
	}

	conn.security = security
	conn.option = option
	return &conn
}

func (c *clientConn) writeHandshake() error {
	const enableMux = false
	paddingLen := mRand.Intn(16)

	var headerLen int
	headerLen += 1  // version
	headerLen += 16 // request iv
	headerLen += 16 // request key
	headerLen += 1  // response header
	headerLen += 1  // option
	headerLen += 1  // padding<<4 || security
	headerLen += 1  // reversed
	headerLen += 1  // command
	if !enableMux {
		headerLen += AddressSerializer.AddrPortLen(c.destination)
	}
	headerLen += paddingLen
	headerLen += 4 // fnv1a hash

	const headerLenBufferLen = 2 + CipherOverhead

	var requestLen int
	requestLen += 16 // auth id
	requestLen += headerLenBufferLen
	requestLen += 8 // connection nonce
	requestLen += headerLen + CipherOverhead

	_requestBuffer := buf.StackNewSize(requestLen)
	defer common.KeepAlive(_requestBuffer)
	requestBuffer := common.Dup(_requestBuffer)
	defer requestBuffer.Release()

	AuthID(c.key, time.Now(), requestBuffer)
	authId := requestBuffer.Bytes()

	headerLenBuffer := buf.With(requestBuffer.ExtendHeader(headerLenBufferLen))
	connectionNonce := requestBuffer.WriteRandom(8)

	common.Must(binary.Write(headerLenBuffer, binary.BigEndian, uint16(headerLen)))
	lengthKey := KDF(c.key, KDFSaltConstVMessHeaderPayloadLengthAEADKey, authId, connectionNonce)[:16]
	lengthNonce := KDF(c.key, KDFSaltConstVMessHeaderPayloadLengthAEADIV, authId, connectionNonce)[:12]
	lengthBlock, err := aes.NewCipher(lengthKey)
	common.Must(err)
	lengthCipher, err := cipher.NewGCM(lengthBlock)
	common.Must(err)
	lengthCipher.Seal(headerLenBuffer.Index(0), lengthNonce, headerLenBuffer.Bytes(), authId)

	headerBuffer := buf.With(requestBuffer.Extend(headerLen))
	common.Must(headerBuffer.WriteByte(Version))
	requestNonce := c.requestNonce[:]
	common.Must1(headerBuffer.Write(requestNonce))
	requestKey := c.requestNonce[:]
	common.Must1(headerBuffer.Write(requestKey))
	headerBuffer.WriteRandom(1) // ignore response header

	common.Must(headerBuffer.WriteByte(c.option))
	common.Must(headerBuffer.WriteByte(byte(paddingLen<<4) | c.security))
	common.Must(headerBuffer.WriteZero())
	common.Must(headerBuffer.WriteByte(c.command))
	if !enableMux {
		common.Must(AddressSerializer.WriteAddrPort(headerBuffer, c.destination))
	}
	if paddingLen > 0 {
		headerBuffer.ExtendHeader(paddingLen)
	}
	headerHash := fnv.New32a()
	common.Must1(headerHash.Write(headerBuffer.Bytes()))
	headerHash.Sum(headerBuffer.Extend(4)[:0])

	headerKey := KDF(c.key, KDFSaltConstVMessHeaderPayloadAEADKey, authId, connectionNonce)[:16]
	headerNonce := KDF(c.key, KDFSaltConstVMessHeaderPayloadAEADIV, authId, connectionNonce)[:12]
	headerBlock, err := aes.NewCipher(headerKey)
	common.Must(err)
	headerCipher, err := cipher.NewGCM(headerBlock)
	common.Must(err)
	headerCipher.Seal(headerBuffer.Index(0), headerNonce, headerBuffer.Bytes(), authId[:])

	_, err = c.upstream.Write(requestBuffer.Bytes())
	if err != nil {
		return err
	}
	c.writer = CreateWriter(c.upstream, requestKey, requestNonce, c.command, c.security, c.option)
	return nil
}

func (c *clientConn) readResponse() error {
	_responseKey := sha256.Sum256(c.requestKey[:])
	responseKey := _responseKey[:16]
	_responseNonce := sha256.Sum256(c.requestNonce[:])
	responseNonce := _responseNonce[:16]

	headerLenKey := KDF(responseKey, KDFSaltConstAEADRespHeaderLenKey)[:16]
	headerLenNonce := vmessaead.KDF(responseNonce, KDFSaltConstAEADRespHeaderLenIV)[:12]
	headerLenCipher := newAes128Gcm(headerLenKey)

	_headerLenBuffer := buf.StackNewSize(2 + CipherOverhead)
	defer common.KeepAlive(_headerLenBuffer)
	headerLenBuffer := common.Dup(_headerLenBuffer)
	defer headerLenBuffer.Release()

	_, err := headerLenBuffer.ReadFullFrom(c.upstream, headerLenBuffer.FreeLen())
	if err != nil {
		return err
	}

	_, err = headerLenCipher.Open(headerLenBuffer.Index(0), headerLenNonce, headerLenBuffer.Bytes(), nil)
	if err != nil {
		return err
	}

	var headerLen uint16
	err = binary.Read(headerLenBuffer, binary.BigEndian, &headerLen)
	if err != nil {
		return err
	}

	headerKey := KDF(responseKey, KDFSaltConstAEADRespHeaderPayloadKey)[:16]
	headerNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderPayloadIV)[:12]
	headerCipher := newAes128Gcm(headerKey)

	_headerBuffer := buf.StackNewSize(int(headerLen) + CipherOverhead)
	defer common.KeepAlive(_headerBuffer)
	headerBuffer := common.Dup(_headerBuffer)
	defer headerBuffer.Release()

	_, err = headerBuffer.ReadFullFrom(c.upstream, headerBuffer.FreeLen())
	if err != nil {
		return err
	}

	_, err = headerCipher.Open(headerBuffer.Index(0), headerNonce, headerBuffer.Bytes(), nil)
	if err != nil {
		return err
	}
	headerBuffer.Truncate(int(headerLen))

	c.reader = CreateReader(c.upstream, responseKey, responseNonce, c.command, c.security, c.option)
	if c.readBuffer != nil {
		c.reader = bufio.NewBufferedReader(c.reader, c.readBuffer)
	}

	return nil
}

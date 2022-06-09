package vmess

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/crypto/sha3"
)

type AEADChunkReader struct {
	upstream      io.Reader
	cipher        cipher.AEAD
	globalPadding sha3.ShakeHash
	nonce         [12]byte
	nonceCount    uint16
}

func NewAEADChunkReader(upstream io.Reader, cipher cipher.AEAD, nonce [12]byte, globalPadding sha3.ShakeHash) *AEADChunkReader {
	return &AEADChunkReader{
		upstream:      upstream,
		cipher:        cipher,
		nonce:         nonce,
		globalPadding: globalPadding,
	}
}

func NewAes128GcmChunkReader(upstream io.Reader, key [16]byte, nonce [12]byte, globalPadding sha3.ShakeHash) *AEADChunkReader {
	return NewAEADChunkReader(upstream, newAes128Gcm(KDF(key, "auth_len")[:16]), nonce, globalPadding)
}

func NewChacha20Poly1305ChunkReader(upstream io.Reader, key [16]byte, nonce [12]byte, globalPadding sha3.ShakeHash) *AEADChunkReader {
	return NewAEADChunkReader(upstream, newChacha20Poly1305(GenerateChacha20Poly1305Key(KDF(key, "auth_len")[:16])), nonce, globalPadding)
}

func (r *AEADChunkReader) Read(p []byte) (n int, err error) {

	_lengthBuffer := buf.StackNewSize(2 + CipherOverhead)
	lengthBuffer := common.Dup(_lengthBuffer)
	_, err = lengthBuffer.ReadFullFrom(r.upstream, lengthBuffer.FreeLen())
	if err != nil {
		return
	}
	_, err = r.cipher.Open(lengthBuffer.Index(0), r.nonce[:], lengthBuffer.Bytes(), nil)
	if err != nil {
		return
	}
	r.nonceCount += 1
	binary.BigEndian.PutUint16(r.nonce[:2], r.nonceCount)
	var length uint16
	err = binary.Read(lengthBuffer, binary.BigEndian, &length)
	if err != nil {
		return
	}
	length += CipherOverhead
	lengthBuffer.Release()
	common.KeepAlive(_lengthBuffer)
	dataLen := int(length)
	var paddingLen int
	if r.globalPadding != nil {
		var hashCode uint16
		common.Must(binary.Read(r.globalPadding, binary.BigEndian, &hashCode))
		paddingLen = int(hashCode % 64)
		dataLen -= paddingLen
	}
	if dataLen <= 0 {
		err = E.Extend(ErrBadLengthChunk, "length=", length, ", padding=", paddingLen)
		return
	}
	var readLen int
	readLen = len(p)
	if readLen > dataLen {
		readLen = dataLen
	} else if readLen < dataLen {
		return 0, io.ErrShortBuffer
	}
	n, err = io.ReadFull(r.upstream, p[:readLen])
	if err != nil {
		return
	}
	_, err = io.CopyN(io.Discard, r.upstream, int64(paddingLen))
	return
}

func (r *AEADChunkReader) Upstream() any {
	return r.upstream
}

type AEADChunkWriter struct {
	upstream      io.Writer
	cipher        cipher.AEAD
	globalPadding sha3.ShakeHash
	maxPacketSize int
	nonce         [12]byte
	nonceCount    uint16
}

func NewAEADChunkWriter(upstream io.Writer, cipher cipher.AEAD, nonce [12]byte, globalPadding sha3.ShakeHash) *AEADChunkWriter {
	maxPacketSize := 65535
	if globalPadding != nil {
		maxPacketSize -= 64
	}
	return &AEADChunkWriter{
		upstream:      upstream,
		cipher:        cipher,
		nonce:         nonce,
		globalPadding: globalPadding,
		maxPacketSize: maxPacketSize,
	}
}

func NewAes128GcmChunkWriter(upstream io.Writer, key [16]byte, nonce [12]byte, globalPadding sha3.ShakeHash) *AEADChunkWriter {
	return NewAEADChunkWriter(upstream, newAes128Gcm(KDF(key, "auth_len")[:16]), nonce, globalPadding)
}

func NewChacha20Poly1305ChunkWriter(upstream io.Writer, key [16]byte, nonce [12]byte, globalPadding sha3.ShakeHash) *AEADChunkWriter {
	return NewAEADChunkWriter(upstream, newChacha20Poly1305(GenerateChacha20Poly1305Key(KDF(key, "auth_len")[:16])), nonce, globalPadding)
}

func (w *AEADChunkWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}

	for pLen := len(p); pLen > 0; {
		var data []byte
		if pLen > w.maxPacketSize {
			p = p[w.maxPacketSize:]
			pLen -= w.maxPacketSize
		} else {
			data = p
			pLen = 0
		}

		dataLength := uint16(len(data))
		var paddingLen uint16
		if w.globalPadding != nil {
			var hashCode uint16
			common.Must(binary.Read(w.globalPadding, binary.BigEndian, &hashCode))
			paddingLen = hashCode % 64
			dataLength += paddingLen
		}
		dataLength -= CipherOverhead

		_lengthBuffer := buf.StackNewSize(2 + CipherOverhead)
		lengthBuffer := common.Dup(_lengthBuffer)
		binary.BigEndian.PutUint16(lengthBuffer.Extend(2), dataLength)
		w.cipher.Seal(lengthBuffer.Index(0), w.nonce[:], lengthBuffer.Bytes(), nil)
		lengthBuffer.Extend(CipherOverhead)
		w.nonceCount += 1
		binary.BigEndian.PutUint16(w.nonce[:2], w.nonceCount)

		_, err = lengthBuffer.WriteTo(w.upstream)
		if err != nil {
			return
		}

		lengthBuffer.Release()
		common.KeepAlive(_lengthBuffer)

		var writeN int
		writeN, err = w.upstream.Write(data)
		if err != nil {
			return
		}
		if paddingLen > 0 {
			_, err = io.CopyN(w.upstream, rand.Reader, int64(paddingLen))
			if err != nil {
				return
			}
		}
		n += writeN
	}
	return
}

func (w *AEADChunkWriter) Upstream() any {
	return w.upstream
}

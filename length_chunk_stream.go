package vmess

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/crypto/sha3"
)

var ErrBadLengthChunk = E.New("bad length chunk")

type StreamChunkReader struct {
	upstream      io.Reader
	chunkMasking  sha3.ShakeHash
	globalPadding sha3.ShakeHash
}

func NewStreamChunkReader(upstream io.Reader, chunkMasking sha3.ShakeHash, globalPadding sha3.ShakeHash) *StreamChunkReader {
	return &StreamChunkReader{
		upstream:      upstream,
		chunkMasking:  chunkMasking,
		globalPadding: globalPadding,
	}
}

func (r *StreamChunkReader) Read(p []byte) (n int, err error) {
	var length uint16
	err = binary.Read(r.upstream, binary.BigEndian, &length)
	if err != nil {
		return
	}
	var paddingLen int
	if r.globalPadding != nil {
		var hashCode uint16
		common.Must(binary.Read(r.globalPadding, binary.BigEndian, &hashCode))
		paddingLen = int(hashCode % 64)
	}
	if r.chunkMasking != nil {
		var hashCode uint16
		common.Must(binary.Read(r.chunkMasking, binary.BigEndian, &hashCode))
		length ^= hashCode
	}
	dataLen := int(length)
	if paddingLen > 0 {
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

func (r *StreamChunkReader) Upstream() any {
	return r.upstream
}

type StreamChunkWriter struct {
	upstream      io.Writer
	chunkMasking  sha3.ShakeHash
	globalPadding sha3.ShakeHash
	maxPacketSize int
}

func NewStreamChunkWriter(upstream io.Writer, chunkMasking sha3.ShakeHash, globalPadding sha3.ShakeHash) *StreamChunkWriter {
	maxPacketSize := 65535
	if globalPadding != nil {
		maxPacketSize -= 64
	}
	return &StreamChunkWriter{
		upstream:      upstream,
		chunkMasking:  chunkMasking,
		globalPadding: globalPadding,
		maxPacketSize: maxPacketSize,
	}
}

func (w *StreamChunkWriter) Write(p []byte) (n int, err error) {
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
		dataLen := uint16(len(data))
		var paddingLen uint16
		if w.globalPadding != nil {
			var hashCode uint16
			common.Must(binary.Read(w.globalPadding, binary.BigEndian, &hashCode))
			paddingLen = hashCode % 64
			dataLen += paddingLen
		}
		if w.chunkMasking != nil {
			var hashCode uint16
			common.Must(binary.Read(w.chunkMasking, binary.BigEndian, &hashCode))
			dataLen ^= hashCode
		}
		err = binary.Write(w.upstream, binary.BigEndian, dataLen)
		if err != nil {
			return
		}
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

func (w *StreamChunkWriter) Upstream() any {
	return w.upstream
}

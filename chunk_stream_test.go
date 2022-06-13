package vmess_test

import (
	"io"
	"testing"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/v2fly/v2ray-core/v5/common/crypto"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/proxy/vmess/encoding"
)

func TestStreamReader(t *testing.T) {
	in, out := io.Pipe()
	defer common.Close(in, out)

	readBuffer := buf.New()
	defer readBuffer.Release()

	randBuffer := buf.New()
	defer randBuffer.Release()

	key := randBuffer.WriteRandom(16)
	nonce := randBuffer.WriteRandom(16)

	streamReader := vmess.NewStreamReader(in, key, nonce)
	chunkReader := vmess.NewStreamChunkReader(streamReader, nil, nil)
	checksumReader := vmess.NewStreamChecksumReader(chunkReader)
	reader := bufio.NewBufferedReader(checksumReader, readBuffer)

	writer := crypto.NewAuthenticationWriter(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.FnvAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		crypto.PlainChunkSizeParser{},
		crypto.NewCryptionWriter(crypto.NewAesEncryptionStream(key[:], nonce[:]), out),
		protocol.TransferTypePacket,
		nil,
	)

	testRead(t, reader, writer)
}

func TestStreamWriter(t *testing.T) {
	in, out := io.Pipe()
	defer common.Close(in, out)

	readBuffer := buf.New()
	defer readBuffer.Release()

	randBuffer := buf.New()
	defer randBuffer.Release()

	key := randBuffer.WriteRandom(16)
	nonce := randBuffer.WriteRandom(16)

	reader := crypto.NewAuthenticationReader(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.FnvAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		crypto.PlainChunkSizeParser{},
		crypto.NewCryptionReader(crypto.NewAesDecryptionStream(key[:], nonce[:]), in),
		protocol.TransferTypePacket,
		nil,
	)

	streamWriter := vmess.NewStreamWriter(out, key, nonce)
	chunkWriter := vmess.NewStreamChunkWriter(streamWriter, nil, nil)
	checksumWriter := vmess.NewStreamChecksumWriter(chunkWriter)
	testWrite(t, reader, checksumWriter)
}

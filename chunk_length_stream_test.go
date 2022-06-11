package vmess_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	vBuf "github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/crypto"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/proxy/vmess/encoding"
	"golang.org/x/crypto/sha3"
)

func TestPlainStreamLengthChunkReader(t *testing.T) {
	in, out := io.Pipe()
	defer common.Close(in, out)
	reader := vmess.NewStreamChunkReader(in, nil, nil)
	writer := crypto.NewChunkStreamWriter(crypto.PlainChunkSizeParser{}, out)
	testRead(t, reader, writer)
}

func TestPlainStreamLengthChunkWriter(t *testing.T) {
	in, out := io.Pipe()
	defer common.Close(in, out)
	reader := crypto.NewChunkStreamReader(crypto.PlainChunkSizeParser{}, in)
	writer := vmess.NewStreamChunkWriter(out, nil, nil)
	testWrite(t, reader, writer)
}

func TestMaskStreamLengthChunkReader(t *testing.T) {
	nonce := make([]byte, 12)
	rand.Read(nonce)

	in, out := io.Pipe()
	defer common.Close(in, out)

	masking := sha3.NewShake128()
	masking.Write(nonce)
	reader := vmess.NewStreamChunkReader(in, masking, nil)

	writer := crypto.NewAuthenticationWriter(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		encoding.NewShakeSizeParser(nonce), out, protocol.TransferTypePacket, nil,
	)

	testRead(t, reader, writer)
}

func TestMaskStreamLengthChunkWriter(t *testing.T) {
	nonce := make([]byte, 12)
	rand.Read(nonce)

	in, out := io.Pipe()
	defer common.Close(in, out)

	reader := crypto.NewAuthenticationReader(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		encoding.NewShakeSizeParser(nonce), in, protocol.TransferTypePacket, nil)

	masking := sha3.NewShake128()
	masking.Write(nonce)
	writer := vmess.NewStreamChunkWriter(out, masking, nil)

	testWrite(t, reader, writer)
}

func TestPaddingStreamLengthChunkReader(t *testing.T) {
	nonce := make([]byte, 12)
	rand.Read(nonce)

	in, out := io.Pipe()
	defer common.Close(in, out)

	padding := sha3.NewShake128()
	padding.Write(nonce)
	reader := vmess.NewStreamChunkReader(in, nil, padding)

	writer := crypto.NewAuthenticationWriter(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		crypto.PlainChunkSizeParser{}, out, protocol.TransferTypePacket, encoding.NewShakeSizeParser(nonce),
	)

	testRead(t, reader, writer)
}

func TestPaddingStreamLengthChunkWriter(t *testing.T) {
	nonce := make([]byte, 12)
	rand.Read(nonce)

	in, out := io.Pipe()
	defer common.Close(in, out)

	reader := crypto.NewAuthenticationReader(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		crypto.PlainChunkSizeParser{}, in, protocol.TransferTypePacket, encoding.NewShakeSizeParser(nonce))

	padding := sha3.NewShake128()
	padding.Write(nonce)
	writer := vmess.NewStreamChunkWriter(out, nil, padding)

	testWrite(t, reader, writer)
}

func TestMaskPaddingStreamLengthChunkReader(t *testing.T) {
	nonce := make([]byte, 12)
	rand.Read(nonce)

	in, out := io.Pipe()
	defer common.Close(in, out)

	masking := sha3.NewShake128()
	masking.Write(nonce)
	reader := vmess.NewStreamChunkReader(in, masking, masking)

	parser := encoding.NewShakeSizeParser(nonce)
	writer := crypto.NewAuthenticationWriter(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		parser, out, protocol.TransferTypePacket, parser,
	)

	testRead(t, reader, writer)
}

func TestMaskPaddingStreamLengthChunkWriter(t *testing.T) {
	nonce := make([]byte, 12)
	rand.Read(nonce)

	in, out := io.Pipe()
	defer common.Close(in, out)

	parser := encoding.NewShakeSizeParser(nonce)
	reader := crypto.NewAuthenticationReader(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		parser, in, protocol.TransferTypePacket, parser)

	masking := sha3.NewShake128()
	masking.Write(nonce)
	writer := vmess.NewStreamChunkWriter(out, masking, masking)

	testWrite(t, reader, writer)
}

func testRead(t *testing.T, reader io.Reader, writer vBuf.Writer) {
	go writer.WriteMultiBuffer(vBuf.MultiBuffer{vBuf.FromBytes([]byte("ping"))})
	content := make([]byte, 4)
	_, err := io.ReadFull(reader, content)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "ping" {
		t.Fatal("bad content: ", string(content))
	}
}

func testWrite(t *testing.T, reader vBuf.Reader, writer io.Writer) {
	go func() {
		_, err := writer.Write([]byte("ping"))
		if err != nil {
			t.Error(err)
		}
	}()
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if mb.String() != "ping" {
		t.Fatal("bad content: ", mb.String())
	}
}

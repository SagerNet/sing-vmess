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
	vmessaead "github.com/v2fly/v2ray-core/v5/proxy/vmess/aead"
	"github.com/v2fly/v2ray-core/v5/proxy/vmess/encoding"
)

func TestAEADReader(t *testing.T) {
	in, out := io.Pipe()
	defer common.Close(in, out)

	readBuffer := buf.New()
	defer readBuffer.Release()

	randBuffer := buf.New()
	defer randBuffer.Release()

	key := randBuffer.WriteRandom(16)
	nonce := randBuffer.WriteRandom(12)

	chunkReader := vmess.NewAes128GcmChunkReader(in, key, nonce, nil)
	cipherReader := vmess.NewAes128GcmReader(chunkReader, key, nonce)

	reader := bufio.NewBufferedReader(cipherReader, readBuffer)

	lengthKey := vmessaead.KDF16(key[:], "auth_len")
	lengthCipher := crypto.NewAesGcm(lengthKey)
	lengthAuth := &crypto.AEADAuthenticator{
		AEAD:                    lengthCipher,
		NonceGenerator:          encoding.GenerateChunkNonce(nonce[:], uint32(lengthCipher.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	sizeParser := encoding.NewAEADSizeParser(lengthAuth)

	writeCipher := crypto.NewAesGcm(key[:])
	writer := crypto.NewAuthenticationWriter(
		&crypto.AEADAuthenticator{
			AEAD:                    writeCipher,
			NonceGenerator:          encoding.GenerateChunkNonce(nonce[:], uint32(writeCipher.NonceSize())),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		sizeParser, out, protocol.TransferTypePacket, nil,
	)

	testRead(t, reader, writer)
}

func TestAEADWriter(t *testing.T) {
	in, out := io.Pipe()
	defer common.Close(in, out)

	randBuffer := buf.New()
	defer randBuffer.Release()

	key := randBuffer.WriteRandom(16)
	nonce := randBuffer.WriteRandom(12)

	lengthKey := vmessaead.KDF16(key[:], "auth_len")
	lengthCipher := crypto.NewAesGcm(lengthKey)
	lengthAuth := &crypto.AEADAuthenticator{
		AEAD:                    lengthCipher,
		NonceGenerator:          encoding.GenerateChunkNonce(nonce[:], uint32(lengthCipher.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	sizeParser := encoding.NewAEADSizeParser(lengthAuth)

	readCipher := crypto.NewAesGcm(key[:])
	reader := crypto.NewAuthenticationReader(
		&crypto.AEADAuthenticator{
			AEAD:                    readCipher,
			NonceGenerator:          encoding.GenerateChunkNonce(nonce[:], uint32(readCipher.NonceSize())),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		sizeParser, in, protocol.TransferTypePacket, nil,
	)

	chunkWriter := vmess.NewAes128GcmChunkWriter(out, key, nonce, nil)
	writer := vmess.NewAes128GcmWriter(chunkWriter, key, nonce)
	testWrite(t, reader, writer)
}

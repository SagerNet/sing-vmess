package vmess_test

import (
	"io"
	"testing"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/v2fly/v2ray-core/v5/common/crypto"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	vmessaead "github.com/v2fly/v2ray-core/v5/proxy/vmess/aead"
	"github.com/v2fly/v2ray-core/v5/proxy/vmess/encoding"
	"golang.org/x/crypto/sha3"
)

func TestAEADLengthChunkReader(t *testing.T) {
	in, out := io.Pipe()
	defer common.Close(in, out)

	var key [16]byte
	var nonce [12]byte

	reader := vmess.NewAes128GcmChunkReader(in, key, nonce, nil)

	lengthKey := vmessaead.KDF16(key[:], "auth_len")
	lengthCipher := crypto.NewAesGcm(lengthKey)
	lengthAuth := &crypto.AEADAuthenticator{
		AEAD:                    lengthCipher,
		NonceGenerator:          encoding.GenerateChunkNonce(nonce[:], uint32(lengthCipher.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	sizeParser := encoding.NewAEADSizeParser(lengthAuth)
	writer := crypto.NewAuthenticationWriter(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		sizeParser, out, protocol.TransferTypePacket, nil,
	)

	testRead(t, reader, writer)
}

func TestAEADLengthChunkWriter(t *testing.T) {
	in, out := io.Pipe()
	defer common.Close(in, out)

	var key [16]byte
	var nonce [12]byte

	lengthKey := vmessaead.KDF16(key[:], "auth_len")
	lengthCipher := crypto.NewAesGcm(lengthKey)
	lengthAuth := &crypto.AEADAuthenticator{
		AEAD:                    lengthCipher,
		NonceGenerator:          encoding.GenerateChunkNonce(nonce[:], uint32(lengthCipher.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	sizeParser := encoding.NewAEADSizeParser(lengthAuth)
	reader := crypto.NewAuthenticationReader(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		sizeParser, in, protocol.TransferTypePacket, nil,
	)

	writer := vmess.NewAes128GcmChunkWriter(out, key, nonce, nil)
	testWrite(t, reader, writer)
}

func TestPaddingAEADLengthChunkReader(t *testing.T) {
	in, out := io.Pipe()
	defer common.Close(in, out)

	var key [16]byte
	var nonce [12]byte

	padding := sha3.NewShake128()
	padding.Write(nonce[:])
	reader := vmess.NewAes128GcmChunkReader(in, key, nonce, padding)

	lengthKey := vmessaead.KDF16(key[:], "auth_len")
	lengthCipher := crypto.NewAesGcm(lengthKey)
	lengthAuth := &crypto.AEADAuthenticator{
		AEAD:                    lengthCipher,
		NonceGenerator:          encoding.GenerateChunkNonce(nonce[:], uint32(lengthCipher.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	sizeParser := encoding.NewAEADSizeParser(lengthAuth)
	writer := crypto.NewAuthenticationWriter(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		sizeParser, out, protocol.TransferTypePacket, encoding.NewShakeSizeParser(nonce[:]),
	)

	testRead(t, reader, writer)
}

func TestPaddingAEADLengthChunkWriter(t *testing.T) {
	in, out := io.Pipe()
	defer common.Close(in, out)

	var key [16]byte
	var nonce [12]byte

	lengthKey := vmessaead.KDF16(key[:], "auth_len")
	lengthCipher := crypto.NewAesGcm(lengthKey)
	lengthAuth := &crypto.AEADAuthenticator{
		AEAD:                    lengthCipher,
		NonceGenerator:          encoding.GenerateChunkNonce(nonce[:], uint32(lengthCipher.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	sizeParser := encoding.NewAEADSizeParser(lengthAuth)
	reader := crypto.NewAuthenticationReader(
		&crypto.AEADAuthenticator{
			AEAD:                    new(encoding.NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		},
		sizeParser, in, protocol.TransferTypePacket, encoding.NewShakeSizeParser(nonce[:]),
	)

	padding := sha3.NewShake128()
	padding.Write(nonce[:])
	writer := vmess.NewAes128GcmChunkWriter(out, key, nonce, padding)
	testWrite(t, reader, writer)
}

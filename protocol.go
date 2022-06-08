package vmess

import (
	"crypto/aes"
	"crypto/md5"
	"encoding/binary"
	"hash/crc32"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	Version = 1
)

const (
	SecurityTypeLegacy           = 1
	SecurityTypeAuto             = 2
	SecurityTypeAes128Gcm        = 3
	SecurityTypeChacha20Poly1305 = 4
	SecurityTypeNone             = 5
	SecurityTypeZero             = 6
)

const (
	CommandTCP = 1
	CommandUDP = 2
	CommandMux = 3
)

const (
	RequestOptionChunkStream         = 1
	RequestOptionConnectionReuse     = 2
	RequestOptionChunkMasking        = 4
	RequestOptionGlobalPadding       = 8
	RequestOptionAuthenticatedLength = 16
)

// nonce in java called iv

const (
	KDFSaltConstAuthIDEncryptionKey             = "AES Auth ID Encryption"
	KDFSaltConstAEADRespHeaderLenKey            = "AEAD Resp Header Len Key"
	KDFSaltConstAEADRespHeaderLenIV             = "AEAD Resp Header Len IV"
	KDFSaltConstAEADRespHeaderPayloadKey        = "AEAD Resp Header Key"
	KDFSaltConstAEADRespHeaderPayloadIV         = "AEAD Resp Header IV"
	KDFSaltConstVMessAEADKDF                    = "VMess AEAD KDF"
	KDFSaltConstVMessHeaderPayloadAEADKey       = "VMess Header AEAD Key"
	KDFSaltConstVMessHeaderPayloadAEADIV        = "VMess Header AEAD Nonce"
	KDFSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length"
	KDFSaltConstVMessHeaderPayloadLengthAEADIV  = "VMess Header AEAD Nonce_Length"
)

const (
	CipherOverhead = 16
)

var AddressSerializer = M.NewSerializer(
	M.AddressFamilyByte(0x01, M.AddressFamilyIPv4),
	M.AddressFamilyByte(0x03, M.AddressFamilyIPv6),
	M.AddressFamilyByte(0x02, M.AddressFamilyFqdn),
	M.PortThenAddress(),
)

func Key(uuid uuid.UUID) (key [16]byte) {
	md5hash := md5.New()
	common.Must1(md5hash.Write(uuid[:]))
	common.Must1(md5hash.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")))
	md5hash.Sum(key[:0])
	return
}

func AuthID(key [16]byte, time time.Time, buffer *buf.Buffer) (authID [16]byte) {
	common.Must(binary.Write(buffer, binary.BigEndian, time.Unix()))
	buffer.WriteRandom(4)
	checksum := crc32.ChecksumIEEE(buffer.Bytes())
	common.Must(binary.Write(buffer, binary.BigEndian, checksum))
	aesBlock, err := aes.NewCipher(common.Dup(key[:]))
	common.Must(err)
	common.KeepAlive(key)
	aesBlock.Encrypt(buffer.Bytes(), buffer.Bytes())
	return
}

func AutoSecurityType() int {
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "s390x" || runtime.GOARCH == "arm64" {
		return SecurityTypeAes128Gcm
	}
	return SecurityTypeChacha20Poly1305
}

package vmess_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/buf"
	"github.com/stretchr/testify/require"
	vmessaead "github.com/v2fly/v2ray-core/v5/proxy/vmess/aead"
	"github.com/v2fly/v2ray-core/v5/proxy/vmess/encoding"
)

func TestAuthId(t *testing.T) {
	user, err := uuid.DefaultGenerator.NewV4()
	require.NoError(t, err)
	buffer := buf.NewSize(16)
	defer buffer.Release()
	cmdKey := vmess.Key(user)
	vmess.AuthID(cmdKey, time.Now(), buffer)
	var authId [16]byte
	copy(authId[:], buffer.Bytes())
	decoder := vmessaead.NewAuthIDDecoderHolder()
	decoder.AddUser(cmdKey, "Demo User")
	_, err = decoder.Match(authId)
	require.NoError(t, err)
}

func TestGenerateChacha20Poly1305Key(t *testing.T) {
	var key [16]byte
	rand.Read(key[:])
	require.Equal(t, vmess.GenerateChacha20Poly1305Key(key[:]), encoding.GenerateChacha20Poly1305Key(key[:]))
}

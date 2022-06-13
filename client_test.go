package vmess_test

import (
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	vUUID "github.com/v2fly/v2ray-core/v5/common/uuid"
	vVmess "github.com/v2fly/v2ray-core/v5/proxy/vmess"
	"github.com/v2fly/v2ray-core/v5/proxy/vmess/encoding"
)

func TestClientSession(t *testing.T) {
	testClientSession(t)
}

func TestClientSessionPadding(t *testing.T) {
	testClientSession(t, vmess.ClientWithGlobalPadding())
}

func TestClientSessionAuthenticatedLength(t *testing.T) {
	testClientSession(t, vmess.ClientWithAuthenticatedLength())
}

func TestClientSessionPaddingAuthenticatedLength(t *testing.T) {
	testClientSession(t, vmess.ClientWithGlobalPadding(), vmess.ClientWithAuthenticatedLength())
}

func testClientSession(t *testing.T, options ...vmess.ClientOption) {
	t.Run("none", func(t *testing.T) {
		testClientSession0(t, protocol.SecurityType_NONE, "none", options...)
	})
	t.Run("aes-128-gcm", func(t *testing.T) {
		testClientSession0(t, protocol.SecurityType_AES128_GCM, "aes-128-gcm", options...)
	})
	t.Run("chacha20-poly1305", func(t *testing.T) {
		testClientSession0(t, protocol.SecurityType_CHACHA20_POLY1305, "chacha20-poly1305", options...)
	})
	t.Run("aes-128-cfb", func(t *testing.T) {
		testClientSession0(t, protocol.SecurityType_LEGACY, "aes-128-cfb", options...)
	})
}

func testClientSession0(t *testing.T, security protocol.SecurityType, securityName string, options ...vmess.ClientOption) {
	user := uuid.New()

	userValidator := vVmess.NewTimedUserValidator(protocol.DefaultIDHash)
	defer common.Close(userValidator)
	userValidator.Add(&protocol.MemoryUser{
		Account: &vVmess.MemoryAccount{
			ID:       protocol.NewID(vUUID.UUID(user)),
			Security: protocol.SecurityType_AES128_GCM,
		},
	})

	sessionHistory := encoding.NewSessionHistory()
	defer common.Close(sessionHistory)

	serverSession := encoding.NewServerSession(userValidator, sessionHistory)

	serverConn, clientConn := net.Pipe()
	defer common.Close(serverConn, clientConn)

	testDestination := "test.com:443"

	go func() {
		client, err := vmess.NewClient(user, "aes-128-gcm", options...)
		require.NoError(t, err)
		conn, err := client.DialConn(clientConn, M.ParseSocksaddr(testDestination))
		require.NoError(t, err)
		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)
	}()

	requestHeader, err := serverSession.DecodeRequestHeader(serverConn)
	require.NoError(t, err)
	require.Equal(t, requestHeader.Destination().NetAddr(), testDestination)
	serverReader := serverSession.DecodeRequestBody(requestHeader, serverConn)
	mb, err := serverReader.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, mb.String(), "ping")
}

package vmess_test

import (
	"net"
	"sync"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
	vBuf "github.com/v2fly/v2ray-core/v5/common/buf"
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
	t.Run("aead-header", func(t *testing.T) {
		testClientSession1(t, security, securityName, 0, options...)
	})
	t.Run("legacy-header", func(t *testing.T) {
		testClientSession1(t, security, securityName, 1, options...)
	})
}

func testClientSession1(t *testing.T, security protocol.SecurityType, securityName string, alterId int, options ...vmess.ClientOption) {
	user, err := uuid.DefaultGenerator.NewV4()
	require.NoError(t, err)

	userValidator := vVmess.NewTimedUserValidator(protocol.DefaultIDHash)
	defer common.Close(userValidator)

	account := &vVmess.MemoryAccount{
		ID:       protocol.NewID(vUUID.UUID(user)),
		Security: security,
	}
	if alterId > 0 {
		account.AlterIDs = protocol.NewAlterIDs(account.ID, uint16(alterId))
	}
	userValidator.Add(&protocol.MemoryUser{
		Account: account,
	})

	sessionHistory := encoding.NewSessionHistory()
	defer common.Close(sessionHistory)

	serverSession := encoding.NewServerSession(userValidator, sessionHistory)

	serverConn, clientConn := net.Pipe()
	defer common.Close(serverConn, clientConn)

	testDestination := "test.com:443"

	var wg sync.WaitGroup
	wg.Add(1)

	client, err := vmess.NewClient(user, securityName, alterId, options...)
	require.NoError(t, err)

	go func() {
		defer wg.Done()
		conn, err := client.DialConn(clientConn, M.ParseSocksaddr(testDestination))
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)
		var pong [4]byte
		_, err = conn.Read(pong[:])
		require.NoError(t, err)
		require.Equal(t, "pong", string(pong[:]))
	}()

	requestHeader, err := serverSession.DecodeRequestHeader(serverConn)
	require.NoError(t, err)
	require.Equal(t, requestHeader.Destination().NetAddr(), testDestination)
	serverReader, err := serverSession.DecodeRequestBody(requestHeader, serverConn)
	require.NoError(t, err)
	mb, err := serverReader.ReadMultiBuffer()
	require.NoError(t, err)
	require.Equal(t, "ping", mb.String())
	serverSession.EncodeResponseHeader(&protocol.ResponseHeader{Option: requestHeader.Option}, serverConn)
	serverWriter, err := serverSession.EncodeResponseBody(requestHeader, serverConn)
	require.NoError(t, err)
	err = serverWriter.WriteMultiBuffer(vBuf.MultiBuffer{vBuf.FromBytes([]byte("pong"))})
	require.NoError(t, err)
	wg.Wait()
}

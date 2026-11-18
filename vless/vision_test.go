package vless

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// Only the write direction determines how Close shuts down the connection.
// The peer reads the raw transport after our direct write, but still expects
// outer TLS records when only our read direction has switched to direct copy.
func TestVisionClose(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		directWrite bool
		directRead  bool
	}{
		{name: "before_direct_copy"},
		{name: "direct_write", directWrite: true},
		{name: "direct_read", directRead: true},
		{name: "both_directions", directWrite: true, directRead: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			closing, peer := visionTestPair(t)
			if test.directWrite {
				visionTestDirectCopy(t, closing, peer)
			}
			if test.directRead {
				visionTestDirectCopy(t, peer, closing)
			}
			if closing.directWrite.Load() != test.directWrite || closing.directRead != test.directRead {
				t.Fatal("connection did not enter the expected direct-copy state")
			}
			if err := closing.Close(); err != nil {
				t.Fatal(err)
			}
			trailing, err := io.ReadAll(peer.netConn)
			if err != nil {
				t.Fatal(err)
			}
			if test.directWrite {
				if len(trailing) != 0 {
					t.Fatalf("outer TLS leaked %d bytes after direct write: %x", len(trailing), trailing)
				}
			} else if len(trailing) < 5 || trailing[0] != 23 {
				// TLS 1.3 encrypts close_notify in an application-data record.
				t.Fatalf("missing encrypted TLS close_notify: %x", trailing)
			}
		})
	}
}

func visionTestDirectCopy(t *testing.T, sender, receiver *VisionConn) {
	t.Helper()
	// The TLS detector has already recognized a TLS 1.3 handshake.
	sender.isTLS = true
	sender.enableXTLS = true
	// Trigger the real Write and Read transitions, including Vision padding.
	record := []byte{23, 3, 3, 0, 4, 1, 2, 3, 4}
	if _, err := sender.Write(record); err != nil {
		t.Fatal(err)
	}
	// A subsequent raw write ensures Read consumes all padding.
	if _, err := sender.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	record = append(record, 42)
	got := make([]byte, len(record))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, record) {
		t.Fatalf("record = %x, want %x", got, record)
	}
	if !sender.directWrite.Load() || !receiver.directRead {
		t.Fatal("connection did not enter direct copy")
	}
}

func visionTestPair(t *testing.T) (*VisionConn, *VisionConn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientRaw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientRaw.Close() })
	serverRaw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serverRaw.Close() })
	deadline := time.Now().Add(5 * time.Second)
	if err := clientRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	clientTLS := tls.Client(clientRaw, &tls.Config{
		ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS13,
	})
	serverTLS := tls.Server(serverRaw, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	})
	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- serverTLS.Handshake() }()
	clientErr := clientTLS.Handshake()
	serverErr := <-serverHandshake
	if clientErr != nil || serverErr != nil {
		t.Fatalf("TLS handshake: client=%v server=%v", clientErr, serverErr)
	}
	var userUUID [16]byte
	userUUID[0] = 1
	client, err := NewVisionConn(clientTLS, clientTLS, userUUID, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewVisionConn(serverTLS, serverTLS, userUUID, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

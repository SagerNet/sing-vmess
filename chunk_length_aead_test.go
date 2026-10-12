package vmess

import (
	"errors"
	"testing"
	"time"
)

type failingTestWriter struct{}

func (failingTestWriter) Write([]byte) (int, error) { return 0, errors.New("upstream write failed") }

func TestAEADChunkWriterUnlocksAfterWriteError(t *testing.T) {
	writer := NewAes128GcmChunkWriter(failingTestWriter{}, make([]byte, 16), make([]byte, 12), nil)
	if _, err := writer.Write([]byte("first")); err == nil {
		t.Fatal("the first write unexpectedly succeeded")
	}
	done := make(chan error, 1)
	go func() {
		_, err := writer.Write([]byte("second"))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the second write unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the second write blocked after the first one failed")
	}
}

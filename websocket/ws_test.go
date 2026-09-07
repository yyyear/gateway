package websocket

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseHandshake(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	request := "GET /ws?token=one HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Authorization: Bearer token\r\n" +
		"X-Trace-ID: first\r\n" +
		"x-trace-id: second\r\n" +
		"Connection: keep-alive, Upgrade\r\n" +
		"Upgrade: WebSocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Protocol: chat, binary\r\n\r\n"
	result, err := parseHandshake([]byte(request), "/ws", 4096, func(origin string) bool { return origin == "" }, []string{"binary", "chat"}, true)
	if err != nil {
		t.Fatalf("parseHandshake: %v", err)
	}
	if result.consumed != len(request) || result.protocol != "chat" {
		t.Fatalf("result = %+v, consumed=%d want %d", result, result.consumed, len(request))
	}
	if got := result.headers["authorization"]; got != "Bearer token" {
		t.Fatalf("authorization header = %q, want %q", got, "Bearer token")
	}
	if got := result.headers["x-trace-id"]; got != "first, second" {
		t.Fatalf("combined trace header = %q, want %q", got, "first, second")
	}
	hash := sha1.Sum([]byte(key + websocketGUID))
	wantAccept := base64.StdEncoding.EncodeToString(hash[:])
	if !bytes.Contains(result.response, []byte("Sec-WebSocket-Accept: "+wantAccept)) {
		t.Fatalf("response does not contain expected accept key: %q", result.response)
	}
}

func TestConnHeaderAccessors(t *testing.T) {
	conn := &Conn{state: &connectionState{headers: map[string]string{
		"authorization": "Bearer token",
		"x-trace-id":    "trace-1",
	}}}

	if got := conn.Header("Authorization"); got != "Bearer token" {
		t.Fatalf("Header(Authorization) = %q, want %q", got, "Bearer token")
	}
	if got := conn.Header(" x-trace-id "); got != "trace-1" {
		t.Fatalf("Header(x-trace-id) = %q, want %q", got, "trace-1")
	}
	if got := conn.Header("missing"); got != "" {
		t.Fatalf("Header(missing) = %q, want empty", got)
	}

	headers := conn.Headers()
	if len(headers) != 2 || headers["authorization"] != "Bearer token" {
		t.Fatalf("Headers() = %#v", headers)
	}
	headers["authorization"] = "changed"
	if got := conn.Header("authorization"); got != "Bearer token" {
		t.Fatalf("Headers() returned an aliased map; Header(authorization) = %q", got)
	}
}

func TestDecodeFrame(t *testing.T) {
	frame := maskedFrame(true, frameText, []byte("hello"), [4]byte{1, 2, 3, 4})
	var buffer bytes.Buffer
	buffer.Write(frame[:3])
	if _, err := decodeFrame(&buffer, 1024); !errors.Is(err, errNeedMoreData) {
		t.Fatalf("partial frame error = %v, want need more data", err)
	}
	buffer.Write(frame[3:])
	decoded, err := decodeFrame(&buffer, 1024)
	if err != nil {
		t.Fatalf("decodeFrame: %v", err)
	}
	if !decoded.fin || decoded.opcode != frameText || string(decoded.payload) != "hello" {
		t.Fatalf("decoded = %+v", decoded)
	}

	var unmasked bytes.Buffer
	unmasked.Write([]byte{0x81, 0x01, 'x'})
	if _, err := decodeFrame(&unmasked, 1024); err == nil {
		t.Fatal("unmasked frame unexpectedly accepted")
	}
}

func TestEncodeFrameLengths(t *testing.T) {
	for _, size := range []int{0, 1, 125, 126, 65535, 65536} {
		payload := bytes.Repeat([]byte{'x'}, size)
		frame, err := encodeFrame(frameBinary, payload)
		if err != nil {
			t.Fatalf("size %d: encodeFrame: %v", size, err)
		}
		var buffer bytes.Buffer
		buffer.Write(maskedFrame(true, frameBinary, payload, [4]byte{9, 8, 7, 6}))
		decoded, err := decodeFrame(&buffer, size)
		if err != nil || len(decoded.payload) != size {
			t.Fatalf("size %d: decode = len %d err %v", size, len(decoded.payload), err)
		}
		if len(frame) < size+2 {
			t.Fatalf("size %d: encoded frame too short", size)
		}
	}
}

func TestServerUpgradeAndEcho(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot reserve local test port: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	h := &testHandler{
		opened:   make(chan struct{}),
		headers:  make(chan map[string]string, 1),
		messages: make(chan Message, 1),
		closed:   make(chan struct{}),
	}
	server := NewServer(addr, WithHandler(h), WithMaxMessageSize(1024), WithMulticore(false))
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()
	select {
	case <-server.Ready():
	case err := <-serveDone:
		t.Fatalf("Serve before ready: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not become ready")
	}

	client, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	request := "GET /ws HTTP/1.1\r\nHost: " + addr + "\r\nAuthorization: Bearer integration-token\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	reader := bufio.NewReader(client)
	handshake, err := readUntil(reader, "\r\n\r\n")
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if !strings.HasPrefix(string(handshake), "HTTP/1.1 101") {
		t.Fatalf("handshake = %q", handshake)
	}
	select {
	case <-h.opened:
	case <-time.After(time.Second):
		t.Fatal("handler did not receive OnOpen")
	}
	select {
	case headers := <-h.headers:
		if got := headers["authorization"]; got != "Bearer integration-token" {
			t.Fatalf("OnOpen authorization header = %q, want %q", got, "Bearer integration-token")
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not receive Upgrade headers")
	}

	if _, err := client.Write(maskedFrame(true, frameText, []byte("hello"), [4]byte{1, 2, 3, 4})); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	select {
	case message := <-h.messages:
		if message.Type != TextMessage || string(message.Data) != "hello" {
			t.Fatalf("message = %+v", message)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not receive message")
	}
	echo, err := readServerFrame(reader)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if echo.opcode != frameText || string(echo.payload) != "hello" {
		t.Fatalf("echo = %+v", echo)
	}

	if _, err := client.Write(maskedFrame(true, frameClose, closePayload(1000, ""), [4]byte{4, 3, 2, 1})); err != nil {
		t.Fatalf("write close: %v", err)
	}
	if _, err := readServerFrame(reader); err != nil {
		t.Fatalf("read close response: %v", err)
	}
	select {
	case <-h.closed:
	case <-time.After(time.Second):
		t.Fatal("handler did not receive OnClose")
	}

	stopCtx, cancel := contextWithTimeout(t, time.Second)
	defer cancel()
	if err := server.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve after Stop: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
}

type testHandler struct {
	opened   chan struct{}
	headers  chan map[string]string
	messages chan Message
	closed   chan struct{}
	once     sync.Once
}

func (h *testHandler) OnOpen(conn *Conn) error {
	if h.headers != nil {
		h.headers <- conn.Headers()
	}
	close(h.opened)
	return nil
}

func (h *testHandler) OnMessage(conn *Conn, message *Message) {
	h.messages <- Message{Type: message.Type, Data: append([]byte(nil), message.Data...)}
	_ = conn.Write(message.Type, message.Data)
}

func (h *testHandler) OnClose(*Conn, error) {
	h.once.Do(func() { close(h.closed) })
}

func maskedFrame(fin bool, opcode byte, payload []byte, mask [4]byte) []byte {
	header := 2
	if len(payload) >= 126 && len(payload) <= 65535 {
		header = 4
	} else if len(payload) > 65535 {
		header = 10
	}
	frame := make([]byte, header+4+len(payload))
	if fin {
		frame[0] = 0x80 | opcode
	} else {
		frame[0] = opcode
	}
	if len(payload) < 126 {
		frame[1] = 0x80 | byte(len(payload))
	} else if len(payload) <= 65535 {
		frame[1] = 0x80 | 126
		binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))
	} else {
		frame[1] = 0x80 | 127
		binary.BigEndian.PutUint64(frame[2:10], uint64(len(payload)))
	}
	offset := header
	copy(frame[offset:offset+4], mask[:])
	for i, value := range payload {
		frame[offset+4+i] = value ^ mask[i&3]
	}
	return frame
}

func readUntil(reader *bufio.Reader, delimiter string) ([]byte, error) {
	var result []byte
	for {
		line, err := reader.ReadBytes('\n')
		result = append(result, line...)
		if err != nil {
			return result, err
		}
		if bytes.Contains(result, []byte(delimiter)) {
			return result, nil
		}
	}
}

func readServerFrame(reader *bufio.Reader) (wsFrame, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return wsFrame{}, err
	}
	second, err := reader.ReadByte()
	if err != nil {
		return wsFrame{}, err
	}
	if second&0x80 != 0 {
		return wsFrame{}, errors.New("server frame is masked")
	}
	length := int(second & 0x7F)
	if length == 126 {
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return wsFrame{}, err
		}
		length = int(binary.BigEndian.Uint16(extended[:]))
	} else if length == 127 {
		return wsFrame{}, errors.New("test frame length is too large")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return wsFrame{}, err
	}
	return wsFrame{fin: first&0x80 != 0, opcode: first & 0x0F, payload: payload}, nil
}

func contextWithTimeout(t *testing.T, timeout time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), timeout)
}

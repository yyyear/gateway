// Package websocket provides a small RFC 6455 server on top of gnet.
//
// gnet is a transport-level event loop, so this package owns the HTTP Upgrade
// handshake and WebSocket frame handling. Handler callbacks run on the gnet
// event loop and must not perform blocking I/O.
package websocket

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/panjf2000/gnet/v2"
)

const (
	// TextMessage and BinaryMessage are the message types accepted by Conn.Write.
	TextMessage   = 1
	BinaryMessage = 2

	defaultPath             = "/ws"
	defaultMaxMessageSize   = 64 * 1024
	defaultMaxHandshakeSize = 16 * 1024
	defaultMaxWriteQueue    = 1 * 1024 * 1024
	readChunkSize           = 32 * 1024

	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	frameContinuation = 0x0
	frameText         = 0x1
	frameBinary       = 0x2
	frameClose        = 0x8
	framePing         = 0x9
	framePong         = 0xA
)

var (
	// ErrServerRunning indicates that Serve was called more than once.
	ErrServerRunning = errors.New("websocket: server is already running")
	// ErrServerNotRunning indicates that no gnet engine is available to stop.
	ErrServerNotRunning = errors.New("websocket: server is not running")
	// ErrConnectionClosed indicates that a connection has already been closed.
	ErrConnectionClosed = errors.New("websocket: connection is closed")
	// ErrConnectionNotOpen indicates that the HTTP Upgrade has not completed.
	ErrConnectionNotOpen = errors.New("websocket: connection is not open")
	// ErrMessageTooLarge indicates that a frame or reassembled message exceeds
	// the configured MaxMessageSize.
	ErrMessageTooLarge = errors.New("websocket: message is too large")
	// ErrWriteQueueFull indicates that a connection's bounded write queue is full.
	ErrWriteQueueFull = errors.New("websocket: write queue is full")
	// ErrPeerClosed is reported to Handler.OnClose for a normal peer close.
	ErrPeerClosed = errors.New("websocket: peer closed the connection")
	// ErrBadHandshake is reported to Handler.OnOpen for a bad HTTP Upgrade.
	messagePool = sync.Pool{
		New: func() interface{} {
			return new(Message)
		},
	}
)

// Message is a complete WebSocket data message. Data is owned by the server
// for the duration of the callback; copy it before retaining it.
type Message struct {
	Type int
	Data []byte
}

// Handler receives lifecycle and data events. Callbacks are invoked serially
// for a connection from its gnet event loop.
type Handler interface {
	OnOpen(*Conn) error
	OnMessage(*Conn, *Message)
	OnClose(*Conn, error)
}

// HandlerFuncs adapts functions to Handler. A nil function is treated as a
// no-op, which is convenient when only one event is needed.
type HandlerFuncs struct {
	Open    func(*Conn) error
	Message func(*Conn, *Message)
	Close   func(*Conn, error)
}

func (h HandlerFuncs) OnOpen(c *Conn) error {
	if h.Open == nil {
		return nil
	}
	return h.Open(c)
}

func (h HandlerFuncs) OnMessage(c *Conn, message *Message) {
	if h.Message != nil {
		h.Message(c, message)
	}
}

func (h HandlerFuncs) OnClose(c *Conn, err error) {
	if h.Close != nil {
		h.Close(c, err)
	}
}

// NopHandler drops all messages and accepts all connections.
type NopHandler struct{}

func (NopHandler) OnOpen(*Conn) error        { return nil }
func (NopHandler) OnMessage(*Conn, *Message) {}
func (NopHandler) OnClose(*Conn, error)      {}

// Option configures a Server. Options should be supplied before Serve starts.
type Option func(*Server)

// WithHandler sets the application callback. If omitted, NopHandler is used.
func WithHandler(handler Handler) Option {
	return func(s *Server) {
		if handler != nil {
			s.handler = handler
		}
	}
}

// WithPath restricts the HTTP Upgrade request to path. The query string is
// ignored. An empty path uses /ws.
func WithPath(path string) Option {
	return func(s *Server) {
		s.path = normalizePath(path)
	}
}

// WithMaxMessageSize bounds both individual frame payloads and reassembled
// fragmented messages.
func WithMaxMessageSize(size int) Option {
	return func(s *Server) {
		s.maxMessageSize = size
	}
}

// WithMaxHandshakeSize bounds the HTTP Upgrade request headers.
func WithMaxHandshakeSize(size int) Option {
	return func(s *Server) {
		s.maxHandshakeSize = size
	}
}

// WithMaxConnections limits accepted TCP connections. A value <= 0 means no
// explicit limit.
func WithMaxConnections(limit int) Option {
	return func(s *Server) {
		s.maxConnections = limit
	}
}

// WithMaxWriteQueue bounds bytes queued for asynchronous writes on one
// connection. A value <= 0 disables this limit.
func WithMaxWriteQueue(size int) Option {
	return func(s *Server) {
		s.maxWriteQueue = size
	}
}

// WithMulticore enables one gnet event loop per available core when true.
func WithMulticore(enabled bool) Option {
	return func(s *Server) {
		s.multicore = enabled
	}
}

// WithLoadBalancing selects gnet's event-loop load-balancing strategy.
func WithLoadBalancing(strategy gnet.LoadBalancing) Option {
	return func(s *Server) {
		s.loadBalancing = strategy
	}
}

// WithReadBufferCap sets gnet's per-connection read buffer capacity.
func WithReadBufferCap(size int) Option {
	return func(s *Server) {
		s.readBufferCap = size
	}
}

// WithWriteBufferCap sets gnet's per-connection write buffer capacity.
func WithWriteBufferCap(size int) Option {
	return func(s *Server) {
		s.writeBufferCap = size
	}
}

// WithTCPKeepAlive configures the TCP keep-alive period. A value <= 0 leaves
// gnet's default unchanged.
func WithTCPKeepAlive(period time.Duration) Option {
	return func(s *Server) {
		s.tcpKeepAlive = period
	}
}

// WithCheckOrigin validates the Origin header during the Upgrade handshake.
// By default any origin is accepted; production deployments should provide an
// allow-list appropriate for their clients.
func WithCheckOrigin(check func(origin string) bool) Option {
	return func(s *Server) {
		s.checkOrigin = check
	}
}

// WithSubprotocols advertises the supplied WebSocket subprotocols and selects
// the first one requested by the client. The server does not require a match
// unless WithRequireSubprotocol is also supplied.
func WithSubprotocols(protocols ...string) Option {
	return func(s *Server) {
		s.subprotocols = append(s.subprotocols[:0], protocols...)
	}
}

// WithRequireSubprotocol rejects an Upgrade when none of the configured
// subprotocols is requested by the client.
func WithRequireSubprotocol(required bool) Option {
	return func(s *Server) {
		s.requireSubprotocol = required
	}
}

// Server is an RFC6455 WebSocket server backed by gnet.
type Server struct {
	subprotocols []string

	addr string
	path string

	maxMessageSize     int
	maxHandshakeSize   int
	maxConnections     int
	maxWriteQueue      int
	readBufferCap      int
	writeBufferCap     int
	checkOrigin        func(string) bool
	ready              chan struct{}
	multicore          bool
	requireSubprotocol bool
	gnet.BuiltinEventEngine
	handler       Handler
	loadBalancing gnet.LoadBalancing
	tcpKeepAlive  time.Duration

	engineMu    sync.RWMutex
	engine      gnet.Engine
	readyOnce   sync.Once
	running     atomic.Bool
	active      atomic.Int64
	connections sync.Map // map[*Conn]struct{}
}

// NewServer creates a gnet WebSocket server. The address may be written as
// ":8080", "127.0.0.1:8080", or a gnet address such as "tcp://:8080".
func NewServer(addr string, options ...Option) *Server {
	s := &Server{
		addr:             addr,
		path:             defaultPath,
		handler:          NopHandler{},
		maxMessageSize:   defaultMaxMessageSize,
		maxHandshakeSize: defaultMaxHandshakeSize,
		maxWriteQueue:    defaultMaxWriteQueue,
		loadBalancing:    gnet.RoundRobin,
		ready:            make(chan struct{}),
	}
	for _, option := range options {
		if option != nil {
			option(s)
		}
	}
	return s
}

// NewServerWithHandler is a convenience constructor for the common case of a
// single application handler.
func NewServerWithHandler(addr string, handler Handler, options ...Option) *Server {
	options = append([]Option{WithHandler(handler)}, options...)
	return NewServer(addr, options...)
}

// Addr returns the configured gnet listen address. For :0, use a concrete
// port when clients need to connect; gnet does not expose a listener address
// through its public Engine API.
func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	return s.addr
}

// Ready is closed after gnet has successfully bound its listener.
func (s *Server) Ready() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.ready
}

// ActiveConnections returns the number of currently accepted TCP connections.
func (s *Server) ActiveConnections() int {
	if s == nil {
		return 0
	}
	return int(s.active.Load())
}

// Serve starts the gnet event loop and blocks until it is stopped or fails.
func (s *Server) Serve() error {
	if s == nil {
		return errors.New("websocket: nil server")
	}
	if err := s.validate(); err != nil {
		return err
	}
	if !s.running.CompareAndSwap(false, true) {
		return ErrServerRunning
	}
	defer s.running.Store(false)

	options := []gnet.Option{
		gnet.WithMulticore(s.multicore),
		gnet.WithLoadBalancing(s.loadBalancing),
	}
	if s.readBufferCap > 0 {
		options = append(options, gnet.WithReadBufferCap(s.readBufferCap))
	}
	if s.writeBufferCap > 0 {
		options = append(options, gnet.WithWriteBufferCap(s.writeBufferCap))
	}
	if s.tcpKeepAlive > 0 {
		options = append(options, gnet.WithTCPKeepAlive(s.tcpKeepAlive))
	}
	return gnet.Run(s, normalizeAddress(s.addr), options...)
}

// Run serves until ctx is cancelled. It is useful when the server owns its
// lifecycle in a larger application.
func (s *Server) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("websocket: nil context")
	}
	done := make(chan error, 1)
	go func() {
		done <- s.Serve()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stopErr := s.Stop(stopCtx)
		cancel()
		serveErr := <-done
		if serveErr != nil && !errors.Is(serveErr, ErrServerNotRunning) {
			return serveErr
		}
		if stopErr != nil && !errors.Is(stopErr, ErrServerNotRunning) {
			return stopErr
		}
		return ctx.Err()
	}
}

// Stop shuts down the gnet engine after closing tracked connections. Pending
// outbound bytes are flushed by gnet when it closes each connection.
func (s *Server) Stop(ctx context.Context) error {
	if s == nil {
		return ErrServerNotRunning
	}
	if ctx == nil {
		return errors.New("websocket: nil context")
	}
	s.engineMu.RLock()
	engine := s.engine
	s.engineMu.RUnlock()
	if !s.running.Load() || engine.Validate() != nil {
		return ErrServerNotRunning
	}
	s.closeAllConnections()
	return engine.Stop(ctx)
}

// Broadcast sends one data message to every currently upgraded connection.
// It returns the number of connections for which the write was queued.
func (s *Server) Broadcast(messageType int, data []byte) (int, error) {
	if s == nil {
		return 0, errors.New("websocket: nil server")
	}
	if err := validateDataMessage(messageType, data, s.maxMessageSize); err != nil {
		return 0, err
	}
	count := 0
	var firstErr error
	s.connections.Range(func(key, _ any) bool {
		conn, ok := key.(*Conn)
		if !ok {
			return true
		}
		if err := conn.Write(messageType, data); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return true
		}
		count++
		return true
	})
	return count, firstErr
}

func (s *Server) validate() error {
	if strings.TrimSpace(s.addr) == "" {
		return errors.New("websocket: listen address is empty")
	}
	if s.maxMessageSize <= 0 {
		return errors.New("websocket: max message size must be positive")
	}
	if s.maxHandshakeSize <= 0 {
		return errors.New("websocket: max handshake size must be positive")
	}
	if s.maxHandshakeSize < 4 {
		return errors.New("websocket: max handshake size is too small")
	}
	if s.requireSubprotocol && len(s.subprotocols) == 0 {
		return errors.New("websocket: subprotocol is required but none is configured")
	}
	address := normalizeAddress(s.addr)
	if !strings.HasPrefix(address, "tcp://") && !strings.HasPrefix(address, "tcp4://") && !strings.HasPrefix(address, "tcp6://") {
		return fmt.Errorf("websocket: unsupported listen address %q", s.addr)
	}
	return nil
}

// OnBoot stores the engine so Stop can be called by the owner and signals
// callers waiting on Ready.
func (s *Server) OnBoot(engine gnet.Engine) (action gnet.Action) {
	s.engineMu.Lock()
	s.engine = engine
	s.engineMu.Unlock()
	s.readyOnce.Do(func() { close(s.ready) })
	return gnet.None
}

func (s *Server) OnShutdown(gnet.Engine) {}

// OnOpen initializes per-connection parser state. Application OnOpen is
// intentionally delayed until the WebSocket Upgrade succeeds.
func (s *Server) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	state := &connectionState{
		server:  s,
		raw:     c,
		scratch: make([]byte, readChunkSize),
	}
	public := &Conn{state: state}
	state.public = public
	c.SetContext(state)
	s.connections.Store(public, struct{}{})

	state.counted = true
	current := s.active.Add(1)
	if s.maxConnections > 0 && current > int64(s.maxConnections) {
		s.active.Add(-1)
		state.counted = false
		return []byte("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"), gnet.Close
	}
	return nil, gnet.None
}

func (s *Server) OnClose(c gnet.Conn, err error) (action gnet.Action) {
	state, _ := c.Context().(*connectionState)
	if state == nil {
		return gnet.None
	}
	if state.counted {
		s.active.Add(-1)
		state.counted = false
	}
	if state.opened {
		state.closed.Store(true)
		handler := s.handler
		if handler != nil {
			invokeClose(handler, state.public, state.closeError(err))
		}
	}
	state.closed.Store(true)
	s.connections.Delete(state.public)
	return gnet.None
}

func (s *Server) OnTraffic(c gnet.Conn) (action gnet.Action) {
	state, ok := c.Context().(*connectionState)
	if !ok || state == nil {
		return gnet.Close
	}
	if err := state.readAvailable(); err != nil {
		state.setCloseError(err)
		return gnet.Close
	}

	for {
		if !state.handshaken {
			action, progressed := s.handleHandshake(state)
			if action != gnet.None {
				return action
			}
			if !progressed {
				return gnet.None
			}
		}

		frame, err := decodeFrame(&state.inbound, s.maxMessageSize)

		switch {
		case errors.Is(err, errNeedMoreData):
			if state.inbound.Len() > s.pendingLimit() {
				return s.protocolClose(state, 1009, ErrMessageTooLarge, "message too large")
			}
			return gnet.None
		case err != nil:
			if errors.Is(err, ErrMessageTooLarge) {
				return s.protocolClose(state, 1009, err, "message too large")
			}
			return s.protocolClose(state, 1002, err, "protocol error")
		}

		if action := s.handleFrame(state, frame); action != gnet.None {
			return action
		}
	}
}

func (s *Server) handleHandshake(state *connectionState) (gnet.Action, bool) {
	result, err := parseHandshake(state.inbound.Bytes(), s.path, s.maxHandshakeSize, s.checkOrigin, s.subprotocols, s.requireSubprotocol)
	if errors.Is(err, errNeedMoreData) {
		if state.inbound.Len() > s.maxHandshakeSize {
			state.setCloseError(errHandshakeTooLarge)
			_, _ = state.raw.Write(httpErrorResponse(431))
			return gnet.Close, true
		}
		return gnet.None, false
	}
	if err != nil {
		state.setCloseError(err)
		status := 400
		if errors.Is(err, errHandshakeTooLarge) {
			status = 431
		}
		var hsErr *handshakeError
		if errors.As(err, &hsErr) {
			status = hsErr.status
		}
		_, _ = state.raw.Write(httpErrorResponse(status))
		return gnet.Close, true
	}

	state.inbound.Next(result.consumed)
	if _, err := state.raw.Write(result.response); err != nil {
		state.setCloseError(err)
		return gnet.Close, true
	}
	state.headers = result.headers
	state.handshaken = true
	state.opened = true
	state.openedAt = time.Now()
	state.openedAtomic.Store(true)

	if handler := s.handler; handler != nil {
		if err := invokeOpen(handler, state.public); err != nil {
			state.setCloseError(err)
			return s.protocolClose(state, 1008, err, "connection rejected"), true
		}
	}
	return gnet.None, true
}

func (s *Server) handleFrame(state *connectionState, frame wsFrame) gnet.Action {
	if frame.opcode == framePing {
		if err := state.writeControl(framePong, frame.payload); err != nil {
			state.setCloseError(err)
			return gnet.Close
		}
		return gnet.None
	}
	if frame.opcode == framePong {
		return gnet.None
	}
	if frame.opcode == frameClose {
		if err := validateClosePayload(frame.payload); err != nil {
			return s.protocolClose(state, 1002, err, "invalid close frame")
		}
		if !state.closeSent.Load() {
			if err := state.writeControl(frameClose, frame.payload); err != nil {
				state.setCloseError(err)
				return gnet.Close
			}
			state.closeSent.Store(true)
		}
		state.setCloseError(ErrPeerClosed)
		return gnet.Close
	}

	switch frame.opcode {
	case frameText, frameBinary:
		if state.fragmentOpcode != 0 {
			return s.protocolClose(state, 1002, errors.New("new data frame while fragmented message is open"), "protocol error")
		}
		if frame.fin {
			if frame.opcode == frameText && !utf8.Valid(frame.payload) {
				return s.protocolClose(state, 1007, errors.New("text message is not valid UTF-8"), "invalid text")
			}
			if err := s.notifyMessage(state, frame.opcode, frame.payload); err != nil {
				return s.protocolClose(state, 1011, err, "handler error")
			}
			return gnet.None
		}
		state.fragmentOpcode = frame.opcode
		state.fragment.Reset()
		_, _ = state.fragment.Write(frame.payload)
		return gnet.None
	case frameContinuation:
		if state.fragmentOpcode == 0 {
			return s.protocolClose(state, 1002, errors.New("unexpected continuation frame"), "protocol error")
		}
		if state.fragment.Len()+len(frame.payload) > s.maxMessageSize {
			return s.protocolClose(state, 1009, ErrMessageTooLarge, "message too large")
		}
		_, _ = state.fragment.Write(frame.payload)
		if !frame.fin {
			return gnet.None
		}
		payload := append([]byte(nil), state.fragment.Bytes()...)
		opcode := state.fragmentOpcode
		state.fragment.Reset()
		state.fragmentOpcode = 0
		if opcode == frameText && !utf8.Valid(payload) {
			return s.protocolClose(state, 1007, errors.New("text message is not valid UTF-8"), "invalid text")
		}
		if err := s.notifyMessage(state, opcode, payload); err != nil {
			return s.protocolClose(state, 1011, err, "handler error")
		}
		return gnet.None
	default:
		return s.protocolClose(state, 1002, errors.New("unsupported frame opcode"), "protocol error")
	}
}

func (s *Server) notifyMessage(state *connectionState, opcode byte, payload []byte) (err error) {
	if s.handler == nil {
		return nil
	}
	msg := messagePool.Get().(*Message)
	msg.Type = int(opcode)
	msg.Data = payload
	defer messagePool.Put(msg)
	return invokeMessage(s.handler, state.public, msg)
}

func (s *Server) protocolClose(state *connectionState, code uint16, err error, reason string) gnet.Action {
	state.setCloseError(err)
	if state.closeSent.CompareAndSwap(false, true) {
		payload := closePayload(code, reason)
		if writeErr := state.writeControl(frameClose, payload); writeErr != nil {
			state.setCloseError(writeErr)
		}
	}
	return gnet.Close
}

func (s *Server) pendingLimit() int {
	limit := s.maxMessageSize + 14
	if limit < s.maxHandshakeSize {
		return s.maxHandshakeSize
	}
	return limit
}

func (s *Server) closeAllConnections() {
	s.connections.Range(func(key, _ any) bool {
		conn, ok := key.(*Conn)
		if !ok {
			return true
		}
		if err := conn.Close(); err != nil {
			_ = conn.CloseNow()
		}
		return true
	})
}

// Conn is one upgraded WebSocket connection.
type Conn struct {
	state *connectionState
}

// Header returns the value of one HTTP header from the WebSocket Upgrade
// request. Header names are matched case-insensitively. If the client sent the
// same header more than once, values are joined with ", ", as defined by the
// HTTP handshake parser.
//
// The value is available from Handler.OnOpen onward. Headers sent after the
// Upgrade are WebSocket data and are not HTTP headers.
func (c *Conn) Header(name string) string {
	if c == nil || c.state == nil {
		return ""
	}
	return c.state.headers[strings.ToLower(strings.TrimSpace(name))]
}

// Headers returns a copy of all HTTP headers from the WebSocket Upgrade
// request. Mutating the returned map does not affect the connection.
func (c *Conn) Headers() map[string]string {
	if c == nil || c.state == nil || len(c.state.headers) == 0 {
		return nil
	}
	result := make(map[string]string, len(c.state.headers))
	for name, value := range c.state.headers {
		result[name] = value
	}
	return result
}

// RemoteAddr returns the peer address captured when the TCP connection opened.
func (c *Conn) RemoteAddr() string {
	if c == nil || c.state == nil {
		return ""
	}
	return c.state.remoteAddr
}

// LocalAddr returns the local listen address captured when the TCP connection opened.
func (c *Conn) LocalAddr() string {
	if c == nil || c.state == nil {
		return ""
	}
	return c.state.localAddr
}

// IsOpen reports whether the HTTP Upgrade completed and the connection has not
// been closed by gnet.
func (c *Conn) IsOpen() bool {
	return c != nil && c.state != nil && c.state.openedAtomic.Load() && !c.state.closed.Load()
}

// Write sends a complete text or binary data message. It is safe to call from
// a handler or another goroutine; gnet performs the actual write asynchronously.
func (c *Conn) Write(messageType int, data []byte) error {
	if c == nil || c.state == nil {
		return ErrConnectionClosed
	}
	if !c.IsOpen() {
		if c.state.closed.Load() {
			return ErrConnectionClosed
		}
		return ErrConnectionNotOpen
	}
	if err := validateDataMessage(messageType, data, c.state.server.maxMessageSize); err != nil {
		return err
	}
	frame, err := encodeFrame(byte(messageType), data)
	if err != nil {
		return err
	}
	return c.state.enqueue(frame)
}

// WriteMessage is an alias for Write using the naming common to WebSocket
// libraries.
func (c *Conn) WriteMessage(messageType int, data []byte) error {
	return c.Write(messageType, data)
}

// WriteText sends a UTF-8 text message.
func (c *Conn) WriteText(text string) error {
	if !utf8.ValidString(text) {
		return errors.New("websocket: text message is not valid UTF-8")
	}
	return c.Write(TextMessage, []byte(text))
}

// WriteBinary sends a binary message.
func (c *Conn) WriteBinary(data []byte) error {
	return c.Write(BinaryMessage, data)
}

// Ping sends a protocol Ping control frame.
func (c *Conn) Ping(data []byte) error {
	return c.writeControl(framePing, data)
}

// Pong sends a protocol Pong control frame.
func (c *Conn) Pong(data []byte) error {
	return c.writeControl(framePong, data)
}

// Close sends a normal close frame and then closes the underlying gnet
// connection. For an immediate close without a frame, use CloseNow.
func (c *Conn) Close() error {
	if c == nil || c.state == nil {
		return ErrConnectionClosed
	}
	if !c.IsOpen() {
		return ErrConnectionClosed
	}
	if c.state.closeSent.CompareAndSwap(false, true) {
		if err := c.writeControl(frameClose, closePayload(1000, "")); err != nil {
			c.state.closeSent.Store(false)
			return err
		}
	}
	return c.state.raw.Close()
}

// CloseNow closes the underlying gnet connection without sending a WebSocket
// close frame.
func (c *Conn) CloseNow() error {
	if c == nil || c.state == nil {
		return ErrConnectionClosed
	}
	return c.state.raw.Close()
}

// Context returns application state attached to the connection.
func (c *Conn) Context() any {
	if c == nil || c.state == nil {
		return nil
	}
	c.state.valueMu.RLock()
	defer c.state.valueMu.RUnlock()
	return c.state.value
}

// SetContext attaches application state to the connection. It does not replace
// gnet's internal connection context.
func (c *Conn) SetContext(value any) {
	if c == nil || c.state == nil {
		return
	}
	c.state.valueMu.Lock()
	c.state.value = value
	c.state.valueMu.Unlock()
}

func (c *Conn) writeControl(opcode byte, data []byte) error {
	if c == nil || c.state == nil {
		return ErrConnectionClosed
	}
	if !c.IsOpen() {
		return ErrConnectionNotOpen
	}
	if len(data) > 125 {
		return ErrMessageTooLarge
	}
	frame, err := encodeFrame(opcode, data)
	if err != nil {
		return err
	}
	return c.state.enqueue(frame)
}

type connectionState struct {
	server *Server
	raw    gnet.Conn
	public *Conn

	scratch        []byte
	inbound        bytes.Buffer
	fragment       bytes.Buffer
	fragmentOpcode byte

	handshaken bool
	opened     bool
	counted    bool
	closeSent  atomic.Bool
	openedAt   time.Time
	closeErr   error
	headers    map[string]string
	remoteAddr string
	localAddr  string

	openedAtomic atomic.Bool
	closed       atomic.Bool
	queuedBytes  atomic.Int64
	valueMu      sync.RWMutex
	value        any
}

func (s *connectionState) readAvailable() error {
	if s.remoteAddr == "" {
		if addr := s.raw.RemoteAddr(); addr != nil {
			s.remoteAddr = addr.String()
		}
		if addr := s.raw.LocalAddr(); addr != nil {
			s.localAddr = addr.String()
		}
	}
	for available := s.raw.InboundBuffered(); available > 0; available = s.raw.InboundBuffered() {
		n := available
		if n > len(s.scratch) {
			n = len(s.scratch)
		}
		read, err := s.raw.Read(s.scratch[:n])
		if read > 0 {
			_, _ = s.inbound.Write(s.scratch[:read])
		}
		if err != nil && read == 0 {
			return err
		}
	}
	return nil
}

func (s *connectionState) enqueue(frame []byte) error {
	if s.closed.Load() {
		return ErrConnectionClosed
	}
	limit := s.server.maxWriteQueue
	frameBytes := int64(len(frame))
	if limit > 0 {
		queued := s.queuedBytes.Add(frameBytes)
		if queued > int64(limit) {
			s.queuedBytes.Add(-frameBytes)
			return ErrWriteQueueFull
		}
	}
	callback := func(_ gnet.Conn, _ error) error {
		if limit > 0 {
			s.queuedBytes.Add(-frameBytes)
		}
		return nil
	}
	if err := s.raw.AsyncWrite(frame, callback); err != nil {
		if limit > 0 {
			s.queuedBytes.Add(-frameBytes)
		}
		return err
	}
	return nil
}

func (s *connectionState) writeControl(opcode byte, data []byte) error {
	frame, err := encodeFrame(opcode, data)
	if err != nil {
		return err
	}
	_, err = s.raw.Write(frame)
	return err
}

func (s *connectionState) setCloseError(err error) {
	if err != nil && s.closeErr == nil {
		s.closeErr = err
	}
}

func (s *connectionState) closeError(gnetErr error) error {
	if s.closeErr != nil {
		return s.closeErr
	}
	return gnetErr
}

type handshakeResult struct {
	response []byte
	protocol string
	consumed int
	headers  map[string]string
}

type handshakeError struct {
	status int
	err    error
}

func (e *handshakeError) Error() string { return e.err.Error() }
func (e *handshakeError) Unwrap() error { return e.err }

var (
	errNeedMoreData      = errors.New("websocket: need more data")
	errHandshakeTooLarge = errors.New("websocket: handshake is too large")
)

func parseHandshake(data []byte, expectedPath string, maxSize int, checkOrigin func(string) bool, protocols []string, requireProtocol bool) (handshakeResult, error) {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		if len(data) > maxSize {
			return handshakeResult{}, errHandshakeTooLarge
		}
		return handshakeResult{}, errNeedMoreData
	}
	consumed := end + 4
	if consumed > maxSize {
		return handshakeResult{}, errHandshakeTooLarge
	}

	lines := strings.Split(string(data[:end]), "\r\n")
	if len(lines) == 0 {
		return handshakeResult{}, &handshakeError{status: 400, err: errors.New("missing request line")}
	}
	request := strings.Fields(lines[0])
	if len(request) != 3 || request[0] != "GET" || request[2] != "HTTP/1.1" {
		return handshakeResult{}, &handshakeError{status: 400, err: errors.New("invalid WebSocket request line")}
	}
	requestPath := request[1]
	if query := strings.IndexByte(requestPath, '?'); query >= 0 {
		requestPath = requestPath[:query]
	}
	if expectedPath != "" && expectedPath != requestPath {
		return handshakeResult{}, &handshakeError{status: 404, err: errors.New("WebSocket path not found")}
	}

	headers := make(map[string]string, len(lines)-1)
	for _, line := range lines[1:] {
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return handshakeResult{}, &handshakeError{status: 400, err: errors.New("invalid HTTP header")}
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if name == "" {
			return handshakeResult{}, &handshakeError{status: 400, err: errors.New("empty HTTP header name")}
		}
		if previous := headers[name]; previous != "" {
			headers[name] = previous + ", " + value
		} else {
			headers[name] = value
		}
	}

	if !headerHasToken(headers["connection"], "upgrade") || !headerHasToken(headers["upgrade"], "websocket") {
		return handshakeResult{}, &handshakeError{status: 400, err: errors.New("missing WebSocket Upgrade headers")}
	}
	if headers["sec-websocket-version"] != "13" {
		return handshakeResult{}, &handshakeError{status: 426, err: errors.New("unsupported WebSocket version")}
	}
	key := strings.TrimSpace(headers["sec-websocket-key"])
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decodedKey) != 16 {
		return handshakeResult{}, &handshakeError{status: 400, err: errors.New("invalid Sec-WebSocket-Key")}
	}
	if checkOrigin != nil && !checkOrigin(headers["origin"]) {
		return handshakeResult{}, &handshakeError{status: 403, err: errors.New("origin is not allowed")}
	}

	protocol := selectSubprotocol(headers["sec-websocket-protocol"], protocols)
	if requireProtocol && protocol == "" {
		return handshakeResult{}, &handshakeError{status: 400, err: errors.New("WebSocket subprotocol is required")}
	}
	acceptHash := sha1.Sum([]byte(key + websocketGUID))
	response := strings.Builder{}
	response.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	response.WriteString("Upgrade: websocket\r\n")
	response.WriteString("Connection: Upgrade\r\n")
	response.WriteString("Sec-WebSocket-Accept: ")
	response.WriteString(base64.StdEncoding.EncodeToString(acceptHash[:]))
	response.WriteString("\r\n")
	if protocol != "" {
		response.WriteString("Sec-WebSocket-Protocol: ")
		response.WriteString(protocol)
		response.WriteString("\r\n")
	}
	response.WriteString("\r\n")
	return handshakeResult{
		consumed: consumed,
		response: []byte(response.String()),
		protocol: protocol,
		headers:  headers,
	}, nil
}

func selectSubprotocol(requested string, supported []string) string {
	if requested == "" || len(supported) == 0 {
		return ""
	}
	wanted := strings.Split(requested, ",")
	for _, candidate := range wanted {
		candidate = strings.TrimSpace(candidate)
		for _, supportedProtocol := range supported {
			if candidate == supportedProtocol {
				return candidate
			}
		}
	}
	return ""
}

func headerHasToken(value, token string) bool {
	for _, candidate := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(candidate), token) {
			return true
		}
	}
	return false
}

type wsFrame struct {
	fin     bool
	opcode  byte
	payload []byte
}

func decodeFrame(buffer *bytes.Buffer, maxPayload int) (wsFrame, error) {
	data := buffer.Bytes()
	if len(data) < 2 {
		return wsFrame{}, errNeedMoreData
	}
	if data[0]&0x70 != 0 {
		return wsFrame{}, errors.New("reserved WebSocket bits are set")
	}
	fin := data[0]&0x80 != 0
	opcode := data[0] & 0x0F
	masked := data[1]&0x80 != 0
	if !masked {
		return wsFrame{}, errors.New("client frame is not masked")
	}
	payloadLength := uint64(data[1] & 0x7F)
	headerLength := 2
	if payloadLength == 126 {
		if len(data) < 4 {
			return wsFrame{}, errNeedMoreData
		}
		payloadLength = uint64(binary.BigEndian.Uint16(data[2:4]))
		if payloadLength < 126 {
			return wsFrame{}, errors.New("non-minimal WebSocket payload length")
		}
		headerLength = 4
	} else if payloadLength == 127 {
		if len(data) < 10 {
			return wsFrame{}, errNeedMoreData
		}
		if data[2]&0x80 != 0 {
			return wsFrame{}, errors.New("WebSocket payload length over uint63")
		}
		payloadLength = binary.BigEndian.Uint64(data[2:10])
		if payloadLength < 65536 {
			return wsFrame{}, errors.New("non-minimal WebSocket payload length")
		}
		headerLength = 10
	}
	if isControlOpcode(opcode) {
		if !fin {
			return wsFrame{}, errors.New("control frame is fragmented")
		}
		if payloadLength > 125 {
			return wsFrame{}, errors.New("control frame payload exceeds 125 bytes")
		}
	} else if opcode != frameContinuation && opcode != frameText && opcode != frameBinary {
		return wsFrame{}, errors.New("unsupported WebSocket opcode")
	}
	if payloadLength > uint64(maxPayload) {
		return wsFrame{}, ErrMessageTooLarge
	}
	total := uint64(headerLength) + 4 + payloadLength
	if total > uint64(len(data)) {
		return wsFrame{}, errNeedMoreData
	}
	frameData := buffer.Next(int(total))
	mask := frameData[headerLength : headerLength+4]
	payload := frameData[headerLength+4:]
	for i := range payload {
		payload[i] ^= mask[i&3]
	}
	return wsFrame{fin: fin, opcode: opcode, payload: payload}, nil
}

func isControlOpcode(opcode byte) bool {
	return opcode == frameClose || opcode == framePing || opcode == framePong
}

func encodeFrame(opcode byte, payload []byte) ([]byte, error) {
	if opcode&0x08 != 0 && (len(payload) > 125 || opcode < frameClose || opcode > framePong) {
		return nil, errors.New("invalid control frame")
	}
	header := 2
	switch {
	case len(payload) < 126:
	case len(payload) <= 65535:
		header += 2
	default:
		header += 8
	}
	frame := make([]byte, header+len(payload))
	frame[0] = 0x80 | opcode
	switch {
	case len(payload) < 126:
		frame[1] = byte(len(payload))
	case len(payload) <= 65535:
		frame[1] = 126
		binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))
	default:
		frame[1] = 127
		binary.BigEndian.PutUint64(frame[2:10], uint64(len(payload)))
	}
	copy(frame[header:], payload)
	return frame, nil
}

func closePayload(code uint16, reason string) []byte {
	if !utf8.ValidString(reason) {
		reason = ""
	}
	if len(reason) > 123 {
		reason = reason[:123]
		for len(reason) > 0 && !utf8.ValidString(reason) {
			reason = reason[:len(reason)-1]
		}
	}
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload[:2], code)
	copy(payload[2:], reason)
	return payload
}

func validateClosePayload(payload []byte) error {
	if len(payload) == 1 {
		return errors.New("close frame has a one-byte payload")
	}
	if len(payload) == 0 {
		return nil
	}
	code := binary.BigEndian.Uint16(payload[:2])
	if !validCloseCode(code) {
		return errors.New("invalid close status code")
	}
	if !utf8.Valid(payload[2:]) {
		return errors.New("close reason is not valid UTF-8")
	}
	return nil
}

func validCloseCode(code uint16) bool {
	switch code {
	case 1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011:
		return true
	default:
		return code >= 3000 && code <= 4999
	}
}

func validateDataMessage(messageType int, data []byte, maxSize int) error {
	if messageType != TextMessage && messageType != BinaryMessage {
		return errors.New("websocket: message type must be text or binary")
	}
	if len(data) > maxSize {
		return ErrMessageTooLarge
	}
	if messageType == TextMessage && !utf8.Valid(data) {
		return errors.New("websocket: text message is not valid UTF-8")
	}
	return nil
}

func httpErrorResponse(status int) []byte {
	text := "Bad Request"
	switch status {
	case 403:
		text = "Forbidden"
	case 404:
		text = "Not Found"
	case 426:
		text = "Upgrade Required"
	case 431:
		text = "Request Header Fields Too Large"
	case 503:
		text = "Service Unavailable"
	}
	return []byte("HTTP/1.1 " + strconv.Itoa(status) + " " + text + "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return defaultPath
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func normalizeAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if strings.Contains(addr, "://") {
		return addr
	}
	return "tcp://" + addr
}

func invokeOpen(handler Handler, conn *Conn) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("websocket: OnOpen panic: %v", recovered)
		}
	}()
	return handler.OnOpen(conn)
}

func invokeMessage(handler Handler, conn *Conn, message *Message) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("websocket: OnMessage panic: %v", recovered)
		}
	}()
	handler.OnMessage(conn, message)
	return nil
}

func invokeClose(handler Handler, conn *Conn, err error) {
	defer func() { _ = recover() }()
	handler.OnClose(conn, err)
}

var _ gnet.EventHandler = (*Server)(nil)
var _ Handler = HandlerFuncs{}

/*
 *
 * Copyright 2014 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// package http2 defines and implements message oriented communication
// channel to complete various transactions (e.g., an RPC).
package http2

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/net/http2"
)

// recvMsg represents the received msg from the transport. All transport
// protocol specific info has been removed.
type recvMsg struct {
	data []byte
	// nil: received some data
	// io.EOF: stream is completed. data is nil.
	// other non-nil error: transport failure. data is nil.
	err error
}

// recvBuffer is an unbounded channel of recvMsg structs.
// Note recvBuffer differs from controlBuffer only in that recvBuffer
// holds a channel of only recvMsg structs instead of objects implementing "item" interface.
// recvBuffer is written to much more often than
// controlBuffer and using strict recvMsg structs helps avoid allocation in "recvBuffer.put"
type recvBuffer struct {
	c       chan recvMsg
	mu      sync.Mutex
	backlog []recvMsg
}

func newRecvBuffer() *recvBuffer {
	b := &recvBuffer{
		c: make(chan recvMsg, 1),
	}
	return b
}

func (b *recvBuffer) put(r recvMsg) {
	b.mu.Lock()
	if len(b.backlog) == 0 {
		select {
		case b.c <- r:
			b.mu.Unlock()
			return
		default:
		}
	}
	b.backlog = append(b.backlog, r)
	b.mu.Unlock()
}

func (b *recvBuffer) load() {
	b.mu.Lock()
	if len(b.backlog) > 0 {
		select {
		case b.c <- b.backlog[0]:
			b.backlog[0] = recvMsg{}
			b.backlog = b.backlog[1:]
		default:
		}
	}
	b.mu.Unlock()
}

// get returns the channel that receives a recvMsg in the buffer.
//
// Upon receipt of a recvMsg, the caller should call load to send another
// recvMsg onto the channel if there is any.
func (b *recvBuffer) get() <-chan recvMsg {
	return b.c
}

// recvBufferReader implements io.Reader interface to read the data from
// recvBuffer.
type recvBufferReader struct {
	ctx    context.Context
	goAway chan struct{}
	recv   *recvBuffer
	last   []byte // Stores the remaining data in the previous calls.
	err    error
}

// Read reads the next len(p) bytes from last. If last is drained, it tries to
// read additional data from recv. It blocks if there no additional data available
// in recv. If Read returns any non-nil error, it will continue to return that error.
func (r *recvBufferReader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	n, r.err = r.read(p)
	return n, r.err
}

func (r *recvBufferReader) read(p []byte) (n int, err error) {
	if r.last != nil && len(r.last) > 0 {
		// Read remaining data left in last call.
		copied := copy(p, r.last)
		r.last = r.last[copied:]
		return copied, nil
	}
	select {
	case <-r.ctx.Done():
		return 0, ContextErr(r.ctx.Err())
	case <-r.goAway:
		return 0, ErrStreamDrain
	case m := <-r.recv.get():
		r.recv.load()
		if m.err != nil {
			return 0, m.err
		}
		copied := copy(p, m.data)
		r.last = m.data[copied:]
		return copied, nil
	}
}

// All items in an out of a controlBuffer should be the same type.
type item interface {
	item()
}

// controlBuffer is an unbounded channel of item.
type controlBuffer struct {
	c       chan item
	mu      sync.Mutex
	backlog []item
}

func newControlBuffer() *controlBuffer {
	b := &controlBuffer{
		c: make(chan item, 1),
	}
	return b
}

func (b *controlBuffer) put(r item) {
	b.mu.Lock()
	if len(b.backlog) == 0 {
		select {
		case b.c <- r:
			b.mu.Unlock()
			return
		default:
		}
	}
	b.backlog = append(b.backlog, r)
	b.mu.Unlock()
}

func (b *controlBuffer) load() {
	b.mu.Lock()
	if len(b.backlog) > 0 {
		select {
		case b.c <- b.backlog[0]:
			b.backlog[0] = nil
			b.backlog = b.backlog[1:]
		default:
		}
	}
	b.mu.Unlock()
}

// get returns the channel that receives an item in the buffer.
//
// Upon receipt of an item, the caller should call load to send another
// item onto the channel if there is any.
func (b *controlBuffer) get() <-chan item {
	return b.c
}

type streamState uint8

const (
	streamActive    streamState = iota
	streamWriteDone             // EndStream sent
	streamReadDone              // EndStream received
	streamDone                  // the entire stream is finished.
)

// Stream represents an RPC in the transport layer.
type Stream struct {
	id uint32
	// nil for client side Stream.
	st *Server
	// ctx is the associated context of the stream.
	ctx context.Context
	// cancel is always nil for client side Stream.
	cancel context.CancelFunc
	// done is closed when the final status arrives.
	done chan struct{}
	// goAway is closed when the server sent GoAways signal before this stream was initiated.
	goAway chan struct{}
	// method records the associated RPC method of the stream.
	method       string
	recvCompress string
	sendCompress string
	buf          *recvBuffer
	trReader     io.Reader
	fc           *inFlow
	recvQuota    uint32

	// TODO: Remote this unused variable.
	// The accumulated inbound quota pending for window update.
	updateQuota uint32

	// Callback to state application's intentions to read data. This
	// is used to adjust flow control, if need be.
	requestRead func(int)

	sendQuotaPool  *quotaPool
	localSendQuota *quotaPool
	// Close headerChan to indicate the end of reception of header metadata.
	headerChan chan struct{}
	// header caches the received header metadata.
	header Metadata
	// The key-value map of trailer metadata.
	trailer Metadata

	mu sync.RWMutex // guard the following
	// headerOK becomes true from the first header is about to send.
	headerOk bool
	state    streamState
	// true iff headerChan is closed. Used to avoid closing headerChan
	// multiple times.
	headerDone bool
	// the status error received from the server.
	status *Status
	// rstStream indicates whether a RST_STREAM frame needs to be sent
	// to the server to signify that this stream is closing.
	rstStream bool
	// rstError is the error that needs to be sent along with the RST_STREAM frame.
	rstError http2.ErrCode
	// bytesSent and bytesReceived indicates whether any bytes have been sent or
	// received on this stream.
	bytesSent     bool
	bytesReceived bool
}

// RecvCompress returns the compression algorithm applied to the inbound
// message. It is empty string if there is no compression applied.
func (s *Stream) RecvCompress() string {
	return s.recvCompress
}

// SetSendCompress sets the compression algorithm to the stream.
func (s *Stream) SetSendCompress(str string) {
	s.sendCompress = str
}

// Done returns a chanel which is closed when it receives the final status
// from the server.
func (s *Stream) Done() <-chan struct{} {
	return s.done
}

// GoAway returns a channel which is closed when the server sent GoAways signal
// before this stream was initiated.
func (s *Stream) GoAway() <-chan struct{} {
	return s.goAway
}

// Header acquires the key-value pairs of header metadata once it
// is available. It blocks until i) the metadata is ready or ii) there is no
// header metadata or iii) the stream is canceled/expired.
func (s *Stream) Header() (Metadata, error) {
	var err error
	select {
	case <-s.ctx.Done():
		err = ContextErr(s.ctx.Err())
	case <-s.goAway:
		err = ErrStreamDrain
	case <-s.headerChan:
		return s.header.Copy(), nil
	}
	// Even if the stream is closed, header is returned if available.
	select {
	case <-s.headerChan:
		return s.header.Copy(), nil
	default:
	}
	return nil, err
}

// Trailer returns the cached trailer metedata. Note that if it is not called
// after the entire stream is done, it could return an empty Metadata. Client
// side only.
func (s *Stream) Trailer() Metadata {
	s.mu.RLock()
	c := s.trailer.Copy()
	s.mu.RUnlock()
	return c
}

// Server returns the underlying Server for the stream.
// The client side stream always returns nil.
func (s *Stream) Server() *Server {
	return s.st
}

// Context returns the context of the stream.
func (s *Stream) Context() context.Context {
	return s.ctx
}

// Method returns the method for the stream.
func (s *Stream) Method() string {
	return s.method
}

// Status returns the status received from the server.
func (s *Stream) Status() *Status {
	return s.status
}

// SetHeader sets the header metadata. This can be called multiple times.
// Server side only.
func (s *Stream) SetHeader(md Metadata) error {
	s.mu.Lock()
	if s.headerOk || s.state == streamDone {
		s.mu.Unlock()
		return ErrIllegalHeaderWrite
	}
	if md.Len() == 0 {
		s.mu.Unlock()
		return nil
	}
	s.header = Join(s.header, md)
	s.mu.Unlock()
	return nil
}

// SetTrailer sets the trailer metadata which will be sent with the RPC status
// by the server. This can be called multiple times. Server side only.
func (s *Stream) SetTrailer(md Metadata) error {
	if md.Len() == 0 {
		return nil
	}
	s.mu.Lock()
	s.trailer = Join(s.trailer, md)
	s.mu.Unlock()
	return nil
}

func (s *Stream) write(m recvMsg) {
	s.buf.put(m)
}

// Read reads all p bytes from the wire for this stream.
func (s *Stream) Read(p []byte) (n int, err error) {
	// Don't request a read if there was an error earlier
	if er := s.trReader.(*transportReader).er; er != nil {
		return 0, er
	}
	s.requestRead(len(p))
	return io.ReadFull(s.trReader, p)
}

// tranportReader reads all the data available for this Stream from the transport and
// passes them into the decoder, which converts them into a gRPC message stream.
// The error is io.EOF when the stream is done or another non-nil error if
// the stream broke.
type transportReader struct {
	reader io.Reader
	// The handler to control the window update procedure for both this
	// particular stream and the associated transport.
	windowHandler func(int)
	er            error
}

func (t *transportReader) Read(p []byte) (n int, err error) {
	n, err = t.reader.Read(p)
	if err != nil {
		t.er = err
		return
	}
	t.windowHandler(n)
	return
}

// finish sets the stream's state and status, and closes the done channel.
// s.mu must be held by the caller.  st must always be non-nil.
func (s *Stream) finish(st *Status) {
	s.status = st
	s.state = streamDone
	close(s.done)
}

// BytesSent indicates whether any bytes have been sent on this stream.
func (s *Stream) BytesSent() bool {
	s.mu.Lock()
	bs := s.bytesSent
	s.mu.Unlock()
	return bs
}

// BytesReceived indicates whether any bytes have been received on this stream.
func (s *Stream) BytesReceived() bool {
	s.mu.Lock()
	br := s.bytesReceived
	s.mu.Unlock()
	return br
}

// GoString is implemented by Stream so context.String() won't
// race when printing %#v.
func (s *Stream) GoString() string {
	return fmt.Sprintf("<stream: %p, %v>", s, s.method)
}

// The key to save transport.Stream in the context.
type streamKey struct{}

// newContextWithStream creates a new context from ctx and attaches stream
// to it.
func newContextWithStream(ctx context.Context, stream *Stream) context.Context {
	return context.WithValue(ctx, streamKey{}, stream)
}

// StreamFromContext returns the stream saved in ctx.
func StreamFromContext(ctx context.Context) (s *Stream, ok bool) {
	s, ok = ctx.Value(streamKey{}).(*Stream)
	return
}

// state of transport
type transportState int

const (
	reachable transportState = iota
	closing
	draining
)

// ServerConfig consists of all the configurations to establish a server transport.
type ServerConfig struct {
	MaxStreams            uint32
	StatsHandler          statsHandler
	KeepaliveParams       ServerParameters
	KeepalivePolicy       EnforcementPolicy
	InitialWindowSize     int32
	InitialConnWindowSize int32
	WriteBufferSize       int
	ReadBufferSize        int
}

// ConnectOptions covers all relevant options for communicating with the server.
type ConnectOptions struct {
	// UserAgent is the application user agent.
	UserAgent string
	// Authority is the :authority pseudo-header to use. This field has no effect if
	// TransportCredentials is set.
	Authority string
	// Dialer specifies how to dial a network address.
	Dialer func(context.Context, string) (net.Conn, error)
	// FailOnNonTempDialError specifies if gRPC fails on non-temporary dial errors.
	FailOnNonTempDialError bool
	// KeepaliveParams stores the keepalive parameters.
	KeepaliveParams ClientParameters
	// StatsHandler stores the handler for stats.
	StatsHandler statsHandler
	// InitialWindowSize sets the initial window size for a stream.
	InitialWindowSize int32
	// InitialConnWindowSize sets the initial window size for a connection.
	InitialConnWindowSize int32
	// WriteBufferSize sets the size of write buffer which in turn determines how much data can be batched before it's written on the wire.
	WriteBufferSize int
	// ReadBufferSize sets the size of read buffer, which in turn determines how much data can be read at most for one read syscall.
	ReadBufferSize int
}

// TargetInfo contains the information of the target such as network address and metadata.
type TargetInfo struct {
	Addr     string
	Metadata interface{}
}

// Options provides additional hints and information for message
// transmission.
type Options struct {
	// Last indicates whether this write is the last piece for
	// this stream.
	Last bool

	// Delay is a hint to the transport implementation for whether
	// the data could be buffered for a batching write. The
	// transport implementation may ignore the hint.
	Delay bool
}

// CallHdr carries the information of a particular RPC.
type CallHdr struct {
	// Host specifies the peer's host.
	Host string

	// Method specifies the operation to perform.
	Method string

	// RecvCompress specifies the compression algorithm applied on
	// inbound messages.
	RecvCompress string

	// SendCompress specifies the compression algorithm applied on
	// outbound message.
	SendCompress string

	// Flush indicates whether a new stream command should be sent
	// to the peer without waiting for the first data. This is
	// only a hint.
	// If it's true, the transport may modify the flush decision
	// for performance purposes.
	// If it's false, new stream will never be flushed.
	Flush bool
}

// streamErrorf creates an StreamError with the specified error code and description.
func streamErrorf(c Code, format string, a ...interface{}) StreamError {
	return StreamError{
		Code: c,
		Desc: fmt.Sprintf(format, a...),
	}
}

// connectionErrorf creates an ConnectionError with the specified error description.
func connectionErrorf(temp bool, e error, format string, a ...interface{}) ConnectionError {
	return ConnectionError{
		Desc: fmt.Sprintf(format, a...),
		temp: temp,
		err:  e,
	}
}

// ConnectionError is an error that results in the termination of the
// entire connection and the retry of all the active streams.
type ConnectionError struct {
	Desc string
	temp bool
	err  error
}

func (e ConnectionError) Error() string {
	return fmt.Sprintf("connection error: desc = %q", e.Desc)
}

// Temporary indicates if this connection error is temporary or fatal.
func (e ConnectionError) Temporary() bool {
	return e.temp
}

// Origin returns the original error of this connection error.
func (e ConnectionError) Origin() error {
	// Never return nil error here.
	// If the original error is nil, return itself.
	if e.err == nil {
		return e
	}
	return e.err
}

var (
	// ErrConnClosing indicates that the transport is closing.
	ErrConnClosing = connectionErrorf(true, nil, "transport is closing")
	// ErrStreamDrain indicates that the stream is rejected by the server because
	// the server stops accepting new RPCs.
	ErrStreamDrain = streamErrorf(codesUnavailable, "the server stops accepting new RPCs")
)

// TODO: See if we can replace StreamError with status package errors.

// StreamError is an error that only affects one stream within a connection.
type StreamError struct {
	Code Code
	Desc string
}

func (e StreamError) Error() string {
	return fmt.Sprintf("stream error: code = %s desc = %q", e.Code, e.Desc)
}

// wait blocks until it can receive from one of the provided contexts or channels
func wait(ctx, tctx context.Context, done, goAway <-chan struct{}, proceed <-chan int) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ContextErr(ctx.Err())
	case <-done:
		return 0, io.EOF
	case <-goAway:
		return 0, ErrStreamDrain
	case <-tctx.Done():
		return 0, ErrConnClosing
	case i := <-proceed:
		return i, nil
	}
}

// ContextErr converts the error from context package into a StreamError.
func ContextErr(err error) StreamError {
	switch err {
	case context.DeadlineExceeded:
		return streamErrorf(codesDeadlineExceeded, "%v", err)
	case context.Canceled:
		return streamErrorf(codesCanceled, "%v", err)
	}
	return streamErrorf(codesInternal, "Unexpected error from context packet: %v", err)
}

// GoAwayReason contains the reason for the GoAway frame received.
type GoAwayReason uint8

const (
	// Invalid indicates that no GoAway frame is received.
	Invalid GoAwayReason = 0
	// NoReason is the default value when GoAway frame is received.
	NoReason GoAwayReason = 1
	// TooManyPings indicates that a GoAway frame with ErrCodeEnhanceYourCalm
	// was received and that the debug data said "too_many_pings".
	TooManyPings GoAwayReason = 2
)

// loopyWriter is run in a separate go routine. It is the single code path that will
// write data on wire.
func loopyWriter(ctx context.Context, cbuf *controlBuffer, handler func(item) error) {
	for {
		select {
		case i := <-cbuf.get():
			cbuf.load()
			if err := handler(i); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	hasData:
		for {
			select {
			case i := <-cbuf.get():
				cbuf.load()
				if err := handler(i); err != nil {
					return
				}
			case <-ctx.Done():
				return
			default:
				if err := handler(&flushIO{}); err != nil {
					return
				}
				break hasData
			}
		}
	}
}

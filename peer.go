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

// Package peer defines various peer information associated with RPCs and
// corresponding utils.
package http2

import (
	"context"
	"net"
)

// Peer contains the information of the peer for an RPC, such as the address
// and authentication information.
type Peer struct {
	// Addr is the peer address.
	Addr net.Addr
}

type peerKey struct{}

// newContextWithPeer creates a new context with peer information attached.
func newContextWithPeer(ctx context.Context, p *Peer) context.Context {
	return context.WithValue(ctx, peerKey{}, p)
}

// PeerFromContext returns the peer saved in ctx.
func PeerFromContext(ctx context.Context) (p *Peer, ok bool) {
	p, ok = ctx.Value(peerKey{}).(*Peer)
	return
}

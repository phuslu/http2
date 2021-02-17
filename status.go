/*
 *
 * Copyright 2020 gRPC authors.
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

// Package status implements errors returned by gRPC.  These errors are
// serialized and transmitted on the wire between server and client, and allow
// for additional data to be transmitted via the Details field in the status
// proto.  gRPC service handlers should return an error created by this
// package, and gRPC clients should expect a corresponding error to be
// returned from the RPC call.
//
// This package upholds the invariants that a non-nil error may not
// contain an OK code, and an OK code must result in a nil error.
package http2

import (
	"context"
	"fmt"
)

// Status represents an RPC status code, message, and details.  It is immutable
// and should be created with New, Newf, or FromProto.
type Status struct {
	c Code
	s string
}

// New returns a Status representing c and msg.
func statusNew(c Code, msg string) *Status {
	return &Status{c: c, s: msg}
}

// Newf returns New(c, fmt.Sprintf(format, a...)).
func statusNewf(c Code, format string, a ...interface{}) *Status {
	return statusNew(c, fmt.Sprintf(format, a...))
}

// Err returns an error representing c and msg.  If c is OK, returns nil.
func statusErr(c Code, msg string) error {
	return statusNew(c, msg).Err()
}

// Errorf returns Error(c, fmt.Sprintf(format, a...)).
func statusErrorf(c Code, format string, a ...interface{}) error {
	return statusErr(c, fmt.Sprintf(format, a...))
}

// Code returns the status code contained in s.
func (s *Status) Code() Code {
	if s == nil || s.s == "" {
		return codesOK
	}
	return Code(s.c)
}

// Message returns the message contained in s.
func (s *Status) Message() string {
	if s == nil || s.s == "" {
		return ""
	}
	return s.s
}

// Err returns an immutable error representing s; returns nil if s.Code() is OK.
func (s *Status) Err() error {
	if s.Code() == codesOK {
		return nil
	}
	return &statusError{e: s.s}
}

// Error wraps a pointer of a status proto. It implements error and Status,
// and a nil *Error should never be returned by this package.
type statusError struct {
	c Code
	e string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("rpc error: code = %s desc = %s", Code(e.c), e.e)
}

// // GRPCStatus returns the Status represented by se.
// func (e *statusError) GRPCStatus() *Status {
// 	return statusFromProto(e.e)
// }

// Is implements future error.Is functionality.
// A Error is equivalent if the code and message are identical.
func (e *statusError) Is(target error) bool {
	tse, ok := target.(*statusError)
	if !ok {
		return false
	}
	return e.e == tse.e
}

// FromError returns a Status representing err if it was produced from this
// package or has a method `GRPCStatus() *Status`. Otherwise, ok is false and a
// Status is returned with codesUnknown and the original error message.
func FromError(err error) (s *Status, ok bool) {
	if err == nil {
		return nil, true
	}
	if se, ok := err.(interface {
		GRPCStatus() *Status
	}); ok {
		return se.GRPCStatus(), true
	}
	return statusNew(codesUnknown, err.Error()), false
}

// Convert is a convenience function which removes the need to handle the
// boolean return value from FromError.
func Convert(err error) *Status {
	s, _ := FromError(err)
	return s
}

// Code returns the Code of the error if it is a Status error, codesOK if err
// is nil, or codesUnknown otherwise.
func WrapCode(err error) Code {
	// Don't use FromError to avoid allocation of OK status.
	if err == nil {
		return codesOK
	}
	if se, ok := err.(interface {
		GRPCStatus() *Status
	}); ok {
		return se.GRPCStatus().Code()
	}
	return codesUnknown
}

// FromContextError converts a context error into a Status.  It returns a
// Status with codesOK if err is nil, or a Status with codesUnknown if err is
// non-nil and not a context error.
func FromContextError(err error) *Status {
	switch err {
	case nil:
		return nil
	case context.DeadlineExceeded:
		return statusNew(codesDeadlineExceeded, err.Error())
	case context.Canceled:
		return statusNew(codesCanceled, err.Error())
	default:
		return statusNew(codesUnknown, err.Error())
	}
}

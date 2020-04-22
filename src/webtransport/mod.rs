// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! WebTransport wire protocol and implementation.

use crate::octets;

/// The QuicTransport ALPN token.
pub const QUICTRANSPORT_ALPN: &[u8] = b"\x09wq-vvv-01";

/// A specialized [`Result`] type for quiche WebTransport operations.
///
/// This type is used throughout quiche's WebTransport public API for any
/// operation that can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// A WebTransport error.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    /// There is no error or no work to do.
    Done,

    /// The provided buffer is too short.
    BufferTooShort,

    /// The QuicTransport server did not provide enough initial unidirectional
    /// stream credit.
    StreamCreditError,

    /// Error originated from the transport layer.
    TransportError(crate::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<super::Error> for Error {
    fn from(err: super::Error) -> Self {
        match err {
            super::Error::Done => Error::Done,

            _ => Error::TransportError(err),
        }
    }
}

impl std::convert::From<octets::BufferTooShortError> for Error {
    fn from(_err: octets::BufferTooShortError) -> Self {
        Error::BufferTooShort
    }
}

/// A QuicTransport connection.
pub struct QuicTransport {}

impl QuicTransport {
    fn new() -> Result<QuicTransport> {
        Ok(QuicTransport {})
    }

    /// Creates a new QuicTransport connection using the provided QUIC
    /// connection.
    ///
    /// If the QUIC connection has a client role, the client indication will be
    /// sent.
    pub fn with_transport(
        conn: &mut super::Connection, origin: &str, path: &str,
    ) -> Result<QuicTransport> {
        let mut qt = QuicTransport::new()?;

        if !conn.is_server {
            if conn.peer_transport_params.initial_max_streams_uni == 0 {
                return Err(Error::StreamCreditError);
            }
            qt.send_client_indication(conn, origin, path)?;
        }

        Ok(qt)
    }

    fn send_client_indication(
        &mut self, conn: &mut super::Connection, origin: &str, path: &str,
    ) -> Result<()> {
        let origin_len = origin.len() as u16;
        let path_len = path.len() as u16;

        if origin_len + path_len > u16::max_value() {
            return Err(Error::BufferTooShort);
        }

        let mut d = vec![0; (origin_len + path_len) as usize];
        let mut b = octets::Octets::with_slice(&mut d);

        // Origin Field
        b.put_u16(0)?;
        b.put_u16(origin_len)?;
        b.put_bytes(origin.as_bytes())?;

        // Path Field
        b.put_u16(1)?;
        b.put_u16(origin_len)?;
        b.put_bytes(origin.as_bytes())?;

        conn.stream_send(2, &d, true)?;

        Ok(())
    }

    /// Sends a QuicTransport Datagram with the specified data.
    pub fn dgram_send(
        &mut self, conn: &mut super::Connection, buf: &[u8],
    ) -> Result<()> {
        let max_size = match conn.peer_transport_params.max_datagram_frame_size {
            Some(v) => v as usize,
            None => {
                return Err(Error::BufferTooShort);
            },
        };

        if buf.len() > max_size
        {
            trace!("attempt to send DATAGRAM larger than peer's max_datagram_frame_size");
            return Err(Error::BufferTooShort);
        }

        let mut d = vec![0; buf.len() as usize];

        let mut b = octets::Octets::with_slice(&mut d);
        b.put_bytes(buf)?;

        let data = super::stream::RangeBuf::from(&d, 0, true);

        conn.dgram_queue.push_writable(data)?;

        Ok(())
    }
}

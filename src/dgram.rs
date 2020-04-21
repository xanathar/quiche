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

use std::collections::VecDeque;

use crate::Error;
use crate::Result;

use crate::stream;

/// Keeps track of Datagram frames.
#[derive(Default)]
pub struct DatagramQueue {
    readable: VecDeque<stream::RangeBuf>,
    writable: VecDeque<stream::RangeBuf>,
    datagram_send_queue_size : usize,
    datagram_recv_queue_size : usize,
}

impl DatagramQueue {
    pub fn new(
        datagram_send_queue_size : u64, 
        datagram_recv_queue_size : u64) -> Self 
    {
        DatagramQueue {
            readable: VecDeque::new(),
            writable: VecDeque::new(),
            datagram_send_queue_size: datagram_send_queue_size as usize,
            datagram_recv_queue_size: datagram_recv_queue_size as usize,
        }
    }

    pub fn push_readable(&mut self, data: stream::RangeBuf) -> Result<()> {
        if self.readable.len() >= self.datagram_recv_queue_size {
            return Err(Error::Done);
        }

        self.readable.push_back(data);

        Ok(())
    }

    pub fn pop_readable(&mut self) -> Option<stream::RangeBuf> {
        self.readable.pop_front()
    }

    pub fn push_writable(&mut self, data: stream::RangeBuf) -> Result<()> {
        if self.writable.len() >= self.datagram_send_queue_size {
            return Err(Error::Done);
        }

        self.writable.push_back(data);

        Ok(())
    }

    pub fn peek_writable(&self) -> Option<usize> {
        let data = self.writable.front()?.as_ref();

        Some(data.len())
    }

    pub fn empty_writable(&self) -> bool {
        self.writable.is_empty()
    }

    pub fn pop_writable(&mut self) -> Option<stream::RangeBuf> {
        self.writable.pop_front()
    }

    pub fn purge_writable(&mut self, f: fn(&[u8]) -> bool) {
        self.writable.retain(|d| !f(d));
    }
}

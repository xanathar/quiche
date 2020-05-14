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

/// Keeps track of Datagram frames.
#[derive(Default)]
pub struct DatagramQueue {
    readable: DatagramVecQueue,
    writable: DatagramVecQueue,
}

#[derive(Default)]
pub struct DatagramVecQueue {
    queue: VecDeque<Vec<u8>>,
    queue_max_len: usize,
    queue_bytes_size: usize,
}

impl DatagramVecQueue {
    fn new(queue_max_len: usize) -> Self {
        DatagramVecQueue {
            queue: VecDeque::new(),
            queue_bytes_size: 0,
            queue_max_len,
        }
    }

    pub fn push(&mut self, data: &[u8]) -> Result<()> {
        if self.queue.len() == self.queue_max_len {
            return Err(Error::Done);
        }

        self.queue.push_back(data.to_vec());
        self.queue_bytes_size += data.len();
        Ok(())
    }

    pub fn peek(&self) -> Option<usize> {
        self.queue.front().map(|d| d.len())
    }

    pub fn pop(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.queue.front() {
            Some(d) =>
                if d.len() > buf.len() {
                    return Err(Error::BufferTooShort);
                },

            None => return Err(Error::Done),
        }

        if let Some(d) = self.queue.pop_front() {
            buf[..d.len()].copy_from_slice(&d);
            self.queue_bytes_size = self.queue_bytes_size.saturating_sub(d.len());
            return Ok(d.len());
        }

        Err(Error::Done)
    }

    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    pub fn pending_bytes(&self) -> usize {
        self.queue_bytes_size
    }

    pub fn purge<F: Fn(&[u8]) -> bool>(&mut self, f: F) {
        self.queue.retain(|d| !f(d));
        self.queue_bytes_size = self.queue.iter()
                                .fold(0, |total, d| total + d.len());
    }
}

impl DatagramQueue {
    pub fn new(readable_max_len : usize,
        writable_max_len : usize,
    ) -> Self {
        DatagramQueue {
            readable: DatagramVecQueue::new(readable_max_len),
            writable: DatagramVecQueue::new(writable_max_len),
        }
    }

    pub fn readable_mut(&mut self) -> &mut DatagramVecQueue {
        &mut self.readable
    }

    pub fn writable_mut(&mut self) -> &mut DatagramVecQueue {
        &mut self.writable
    }

    pub fn writable(&self) -> &DatagramVecQueue {
        &self.writable
    }
}

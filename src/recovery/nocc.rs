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

//! CUBIC Congestion Control
//!
//! This implementation is based on the following RFC:
//!
//! https://tools.ietf.org/html/rfc8312
//!
//! Note that Slow Start can use HyStart++ when enabled.

use std::time::Instant;

use crate::packet;
use crate::recovery::CongestionControlOps;
use crate::recovery::Recovery;
use crate::recovery::Sent;

pub static NoCC: CongestionControlOps = CongestionControlOps {
    on_packet_sent,
    on_packet_acked,
    congestion_event,
    collapse_cwnd,
};

fn collapse_cwnd(_r: &mut Recovery) {
}

fn on_packet_sent(r: &mut Recovery, _sent_bytes: usize, _now: Instant) {
    r.congestion_window = usize::max_value();
    r.bytes_in_flight += sent_bytes;
}

fn on_packet_acked(
    r: &mut Recovery, _epoch: packet::Epoch, _packet: &Sent, _now: Instant,
) {
    r.congestion_window = usize::max_value();
    r.bytes_in_flight = r.bytes_in_flight.saturating_sub(packet.size);
}

fn congestion_event(
    _r: &mut Recovery, _time_sent: Instant, _epoch: packet::Epoch, _now: Instant,
) {
}


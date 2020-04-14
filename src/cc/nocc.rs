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

use std::time::Duration;
use std::time::Instant;

use crate::cc;
use crate::recovery::Sent;

/// NoCC [dummy] congestion control implementation.
pub struct NoCC {
}

impl cc::CongestionControl for NoCC {
    fn new() -> Self
    where
        Self: Sized,
    {
        NoCC {
        }
    }

    fn cwnd(&self) -> usize {
        1 << 20
    }

    fn collapse_cwnd(&mut self) {
    }

    fn bytes_in_flight(&self) -> usize {
        0
    }

    fn decrease_bytes_in_flight(&mut self, bytes_in_flight: usize) {
    }

    fn congestion_recovery_start_time(&self) -> Option<Instant> {
        None
    }

    fn on_packet_sent_cc(
        &mut self, bytes_sent: usize, _now: Instant, _trace_id: &str,
    ) {
        
    }

    fn on_packet_acked_cc(
        &mut self, packet: &Sent, _srtt: Duration, _min_rtt: Duration,
        app_limited: bool, _now: Instant, _trace_id: &str,
    ) {
    }

    fn congestion_event(
        &mut self, time_sent: Instant, now: Instant, _trace_id: &str,
    ) {
    }
}

impl std::fmt::Debug for NoCC {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "NoCC!",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE_ID: &str = "test_id";

    #[test]
    fn reno_init() {
        let cc = cc::new_congestion_control(cc::Algorithm::Reno);

        assert!(cc.cwnd() > 0);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn reno_send() {
        let mut cc = cc::new_congestion_control(cc::Algorithm::Reno);
        let now = Instant::now();

        cc.on_packet_sent_cc(1000, now, TRACE_ID);

        assert_eq!(cc.bytes_in_flight(), 1000);
    }

    #[test]
    fn reno_slow_start() {
        let mut cc = cc::new_congestion_control(cc::Algorithm::Reno);
        let now = Instant::now();

        let p = Sent {
            pkt_num: 0,
            frames: vec![],
            time: now,
            size: 5000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: std::time::Instant::now(),
            recent_delivered_packet_sent_time: std::time::Instant::now(),
            is_app_limited: false,
        };

        // Send 5k x 4 = 20k, higher than default cwnd(~15k)
        // to become no longer app limited.
        cc.on_packet_sent_cc(p.size, now, TRACE_ID);
        cc.on_packet_sent_cc(p.size, now, TRACE_ID);
        cc.on_packet_sent_cc(p.size, now, TRACE_ID);
        cc.on_packet_sent_cc(p.size, now, TRACE_ID);

        let cwnd_prev = cc.cwnd();

        cc.on_packet_acked_cc(
            &p,
            Duration::new(0, 1),
            Duration::new(0, 1),
            false,
            now,
            TRACE_ID,
        );

        // Check if cwnd increased by packet size (slow start).
        assert_eq!(cc.cwnd(), cwnd_prev + p.size);
    }

    #[test]
    fn reno_congestion_event() {
        let mut cc = cc::new_congestion_control(cc::Algorithm::Reno);
        let prev_cwnd = cc.cwnd();
        let now = Instant::now();

        cc.congestion_event(now, now, TRACE_ID);

        // In Reno, after congestion event, cwnd will be cut in half.
        assert_eq!(prev_cwnd / 2, cc.cwnd());
    }

    #[test]
    fn reno_congestion_avoidance() {
        let mut cc = cc::new_congestion_control(cc::Algorithm::Reno);
        let prev_cwnd = cc.cwnd();
        let now = Instant::now();

        // Send 20K bytes.
        cc.on_packet_sent_cc(20000, now, TRACE_ID);

        cc.congestion_event(now, now, TRACE_ID);

        // In Reno, after congestion event, cwnd will be cut in half.
        assert_eq!(prev_cwnd / 2, cc.cwnd());

        let p = Sent {
            pkt_num: 0,
            frames: vec![],
            time: now,
            size: 5000,
            ack_eliciting: true,
            in_flight: true,
            delivered: 0,
            delivered_time: std::time::Instant::now(),
            recent_delivered_packet_sent_time: std::time::Instant::now(),
            is_app_limited: false,
        };

        let prev_cwnd = cc.cwnd();

        // Ack 5000 bytes.
        cc.on_packet_acked_cc(
            &p,
            Duration::new(0, 1),
            Duration::new(0, 1),
            false,
            now,
            TRACE_ID,
        );

        // Check if cwnd increase is smaller than a packet size (congestion
        // avoidance).
        assert!(cc.cwnd() < prev_cwnd + 1111);
    }

    #[test]
    fn reno_collapse_cwnd() {
        let mut cc = cc::new_congestion_control(cc::Algorithm::Reno);

        // cwnd will be reset
        cc.collapse_cwnd();
        assert_eq!(cc.cwnd(), cc::MINIMUM_WINDOW);
    }
}

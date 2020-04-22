// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <ev.h>

#ifdef __MACH__
    #include <mach/mach_init.h>
    #include <mach/thread_act.h>
    #include <mach/mach_port.h>
    #include <mach/clock.h>
    #include <mach/mach.h>
#endif

#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

#define BYTES_BEFORE_BENCHMARK_START (128L * (1L << 20))
#define BYTES_BEFORE_BENCHMARK_TARGET (4L * (1L << 30))

#define MAX_PACKET_SIZE 16300

#define DBG_FPRINTF(...)

typedef enum _OperationMode 
{
    OPMODE_QUICHE_COPY,
    OPMODE_QUICHE_NOCOPY,
    OPMODE_RAW_UDP
} OperationMode;


static OperationMode op_mode;

struct conn_io {
    ev_timer timer;

    int sock;

    quiche_conn *conn;
};

static int benchmark_handle_dgram(uint32_t datagram_seq, uint8_t *dgram_data, ssize_t dgram_len);

static void debug_log(const char *line, void *argp) {
    DBG_FPRINTF(stderr, "%s\n", line);
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_PACKET_SIZE];

    while (1) {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out));

        if (written == QUICHE_ERR_DONE) {
            DBG_FPRINTF(stderr, "done writing\n");
            break;
        }

        if (written < 0) {
            DBG_FPRINTF(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        ssize_t sent = send(conn_io->sock, out, written, 0);
        if (sent != written) {
            perror("failed to send");
            return;
        }

        DBG_FPRINTF(stderr, "sent %zd bytes\n", sent);
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
}

static void recv_cb_udp(EV_P_ ev_io *w, int revents) {
    struct conn_io *conn_io = w->data;

    static uint8_t buf[65535];

    while (1) {
        ssize_t read = recv(conn_io->sock, buf, sizeof(buf), 0);
        uint32_t datagram_seq = 0;

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                DBG_FPRINTF(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        memcpy(&datagram_seq, buf, sizeof(uint32_t));

        if (benchmark_handle_dgram(datagram_seq, buf, read)) {
            printf("UDP done\n");
            exit(0);
        }
    }
}


static void recv_cb(EV_P_ ev_io *w, int revents) {
    static bool req_sent = false;

    struct conn_io *conn_io = w->data;

    static uint8_t buf[65535];

    while (1) {
        ssize_t read = recv(conn_io->sock, buf, sizeof(buf), 0);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                DBG_FPRINTF(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read);

        if (done == QUICHE_ERR_DONE) {
            DBG_FPRINTF(stderr, "done reading\n");
            break;
        }

        if (done < 0) {
            DBG_FPRINTF(stderr, "failed to process packet\n");
            return;
        }

        DBG_FPRINTF(stderr, "recv %zd bytes\n", done);
    }

    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed\n");

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    if (quiche_conn_is_established(conn_io->conn) && !req_sent) {
        const uint8_t *app_proto;
        size_t app_proto_len;

        quiche_conn_application_proto(conn_io->conn, &app_proto, &app_proto_len);

        DBG_FPRINTF(stderr, "connection established: %.*s\n",
                (int) app_proto_len, app_proto);

        const static uint8_t r[] = "DGRAM-START\r\n";
        if (quiche_conn_stream_send(conn_io->conn, 4, r, sizeof(r), false) < 0) {
            DBG_FPRINTF(stderr, "failed to send DGRAM-START request\n");
            return;
        }

        DBG_FPRINTF(stderr, "sent DGRAM-START request\n");

        req_sent = true;
    }

    if (quiche_conn_is_established(conn_io->conn)) {
        uint64_t s = 0;
        quiche_stream_iter *readable;
        uint8_t data_buf[65536];

        while(1) { 
            uint32_t datagram_seq = 0;
            uint8_t *dgram_data = NULL;
            ssize_t dgram_len = 0;
            
            if (op_mode == OPMODE_QUICHE_COPY) {
                dgram_len = quiche_conn_dgram_recv_on_buf(conn_io->conn, data_buf, 65536);
                dgram_data = data_buf;
            } else {
                dgram_len = quiche_conn_dgram_recv(conn_io->conn, &dgram_data);
            }

            if (dgram_len < 0) 
                break;
            
            memcpy(&datagram_seq, dgram_data, sizeof(uint32_t));

            if (benchmark_handle_dgram(datagram_seq, dgram_data, dgram_len)) {
                const static uint8_t r[] = "DGRAM-STOP\r\n";
                ssize_t res = quiche_conn_stream_send(conn_io->conn, 4, r, sizeof(r), true);
                if (res < 0) {
                    DBG_FPRINTF(stderr, "failed to send DGRAM-STOP request %zd\n", res);
                } else {
                    DBG_FPRINTF(stderr, "sent DGRAM-STOP request\n");
                }
            }

            if (op_mode == OPMODE_QUICHE_NOCOPY) {
                quiche_conn_dgram_free(conn_io->conn, dgram_data, dgram_len);
            }
        } 

        readable = quiche_conn_readable(conn_io->conn);

        while (quiche_stream_iter_next(readable, &s)) {
            DBG_FPRINTF(stderr, "stream %" PRIu64 " is readable\n", s);

            bool fin = false;
            ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s,
                                                       buf, sizeof(buf),
                                                       &fin);
            if (recv_len < 0) {
                break;
            }

            //printf("%.*s", (int) recv_len, buf);
            printf("received %zd bytes on stream %llu, [%s]\n", recv_len, s, fin ? "FIN" : "...");

            if (fin) {
                if (quiche_conn_close(conn_io->conn, true, 0, NULL, 0) < 0) {
                    DBG_FPRINTF(stderr, "failed to close connection\n");
                }
            }
        }

        quiche_stream_iter_free(readable);
    }

    flush_egress(loop, conn_io);
}

/*
This function gets called each dgram. Must compute stats and return 1 when prog should terminate (1GB ?)
And measure time! that's the point.
*/

double timeval_diff_sec(struct timespec *end, struct timespec *start)
{
    double tend = end->tv_sec;
    double tstart = start->tv_sec;

    tend += ((double)end->tv_nsec) / 1000000000.0;
    tstart += ((double)start->tv_nsec) / 1000000000.0;

    return tend - tstart;
}

static void get_cpu_time(struct timespec *ts)
{
    #if defined(__MACH__)
        thread_port_t thread = mach_thread_self();
        mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
        thread_basic_info_data_t info;

        int kr = thread_info(thread, THREAD_BASIC_INFO, (thread_info_t) &info, &count);
        if (kr != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), thread);
            ts->tv_sec = 0;
            ts->tv_nsec = 0;
            return;
        }

        ts->tv_sec = info.user_time.seconds + info.system_time.seconds;
        ts->tv_nsec = (info.user_time.microseconds + info.system_time.microseconds) * 1000L;

        mach_port_deallocate(mach_task_self(), thread);
    #elif defined(_POSIX_CPUTIME)
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, ts);
    #elif defined(_POSIX_THREAD_CPUTIME)
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, ts);
    #else
        ts->tv_sec = 0;
        ts->tv_nsec = 0;
    #endif
}

static void get_mono_time(struct timespec *ts)
{
    #if defined(__MACH__)
        clock_serv_t cclock;
        mach_timespec_t macts;
        host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
        clock_get_time(cclock, &macts);
        mach_port_deallocate(mach_task_self(), cclock);
        ts->tv_sec = macts.tv_sec;
        ts->tv_nsec = macts.tv_nsec;
    #elif defined(_POSIX_CPUTIME)
        clock_gettime(CLOCK_MONOTONIC, ts);
    #else
        ts->tv_sec = 0;
        ts->tv_nsec = 0;
    #endif
}

static int benchmark_handle_dgram(uint32_t datagram_seq, uint8_t *dgram_data, ssize_t dgram_len) {
    static ssize_t stats_total_bytes = 0;
    static struct timespec start_cpu_time, start_mono_time;
    static int terminate = 0;
    static int started = 0;
    static ssize_t packet_size = 0;

    double time_cpu_spent, time_mono_spent, bandwidth;
    struct timespec stop_cpu_time, stop_mono_time;
    uint32_t last_packet_expected, last_packet_rcvd, packet_loss_est;

    if (terminate) {
        return 1;
    }

    if (stats_total_bytes == 0 && !started) {
        printf("Datagram benchmark ramping up...\n");
    }

    stats_total_bytes += dgram_len;

    if (!started) {
        if (stats_total_bytes < BYTES_BEFORE_BENCHMARK_START) {
            return 0;
        }

        started = 1;
        stats_total_bytes = 0;

        packet_size = dgram_len;
        
        get_cpu_time(&start_cpu_time);
        get_mono_time(&start_mono_time);

        printf("Datagram benchmark started!\n");
        return 0;
    }

    if (stats_total_bytes < BYTES_BEFORE_BENCHMARK_TARGET) {
        return 0;
    }

    get_cpu_time(&stop_cpu_time);
    get_mono_time(&stop_mono_time);

    time_cpu_spent = timeval_diff_sec(&stop_cpu_time, &start_cpu_time);
    time_mono_spent = timeval_diff_sec(&stop_mono_time, &start_mono_time);
    bandwidth = (((double)stats_total_bytes) / time_mono_spent) / ((double)(1 << 20));

    last_packet_expected = (uint32_t)((BYTES_BEFORE_BENCHMARK_TARGET + BYTES_BEFORE_BENCHMARK_START) / packet_size);
    memcpy(&last_packet_rcvd, dgram_data, sizeof(uint32_t));
    packet_loss_est = last_packet_rcvd - last_packet_expected;

    printf("--------------------------------------------------\n");
    printf("Wall time sec. : %f\n", time_mono_spent);
    printf("CPU time sec.  : %f\n", time_cpu_spent);
    printf("Est. bandwidth : %f MiB/s\n", bandwidth);
    printf("Est. pkts lost : %d (recv %d, last id %d)\n", packet_loss_est, 
           last_packet_expected, last_packet_rcvd);
    printf("Total datasent : %zd bytes\n", stats_total_bytes);
    printf("--------------------------------------------------\n");

    terminate = 1;
    return 1;
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;

    if (op_mode == OPMODE_RAW_UDP) {
        return;
    }

    quiche_conn_on_timeout(conn_io->conn);

    DBG_FPRINTF(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;

        quiche_conn_stats(conn_io->conn, &stats);

        DBG_FPRINTF(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns\n",
                stats.recv, stats.sent, stats.lost, stats.rtt);

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }
}

static int32_t set_sock_buf(int sock, int buf, int32_t size) {
    int32_t buffer_size = size;
    socklen_t len = sizeof(int32_t);
    if (setsockopt(sock, SOL_SOCKET, buf, &buffer_size, len)) {
        return -1;
    }
    buffer_size = 0;
    getsockopt(sock, SOL_SOCKET, buf, &buffer_size, &len);
    return buffer_size;
}

int main(int argc, char *argv[]) {
    const char *host = argv[1];
    const char *port = argv[2];
    const char *cmdline_op_mode = argv[3];

    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    int32_t buf_size;

    //quiche_enable_debug_logging(debug_log, NULL);
    debug_log("", NULL);

    struct addrinfo *peer;
    if (getaddrinfo(host, port, &hints, &peer) != 0) {
        fprintf(stderr, "failed to resolve host");
        return -1;
    }

    if (cmdline_op_mode == NULL) {
        fprintf(stderr, "op_mode not specified: [copy|nocopy|rawudp]");
        return -1;
    } else if (0 == strcmp(cmdline_op_mode, "copy")) {
        op_mode = OPMODE_QUICHE_COPY;
        printf("Starting in QUIC+COPY mode\n");
    } else if (0 == strcmp(cmdline_op_mode, "nocopy")) {
        op_mode = OPMODE_QUICHE_NOCOPY;
        printf("Starting in QUIC+NO_COPY mode\n");
    } else if (0 == strcmp(cmdline_op_mode, "rawudp")) {
        printf("Starting in UDP mode\n");
        op_mode = OPMODE_RAW_UDP;
    } else {
        fprintf(stderr, "op_mode invalid: must be 'copy', 'nocopy' or 'rawudp'");
        return -1;
    }

    int sock = socket(peer->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    buf_size = set_sock_buf(sock, SO_RCVBUF, 4 * 1024 * 1024);
    if (buf_size < 0) {
        perror("failed to set receive buffer size");
        return -1;
    } else {
        printf("receive buffer size: %d\n", buf_size);
    }

    buf_size = set_sock_buf(sock, SO_SNDBUF, 4 * 1024 * 1024);
    if (buf_size < 0) {
        perror("failed to set send buffer size");
        return -1;
    } else {
        printf("send buffer size: %d\n", buf_size);
    }

    if (connect(sock, peer->ai_addr, peer->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }
    
    quiche_conn *conn = NULL;
    quiche_config *config = NULL;
    
    if (op_mode != OPMODE_RAW_UDP) {
        config = quiche_config_new(0xbabababa);
        if (config == NULL) {
            DBG_FPRINTF(stderr, "failed to create config\n");
            return -1;
        }

        quiche_config_set_application_protos(config,
            (uint8_t *) "\x0dtest-dgram-01", 14);

        quiche_config_set_max_idle_timeout(config, 5000000);
        quiche_config_set_max_packet_size(config, MAX_PACKET_SIZE);
        quiche_config_set_initial_max_data(config, 10000000);
        quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
        quiche_config_set_initial_max_stream_data_uni(config, 1000000);
        quiche_config_set_initial_max_streams_bidi(config, 100);
        quiche_config_set_initial_max_streams_uni(config, 100);
        quiche_config_set_disable_active_migration(config, true);
        quiche_config_set_max_datagram_frame_size(config, 65535);
        quiche_config_set_cc_algorithm(config, QUICHE_CC_NOCC);

        if (getenv("SSLKEYLOGFILE")) {
        quiche_config_log_keys(config);
        }

        uint8_t scid[LOCAL_CONN_ID_LEN];
        int rng = open("/dev/urandom", O_RDONLY);
        if (rng < 0) {
            perror("failed to open /dev/urandom");
            return -1;
        }

        ssize_t rand_len = read(rng, &scid, sizeof(scid));
        if (rand_len < 0) {
            perror("failed to create connection ID");
            return -1;
        }

        conn = quiche_connect(host, (const uint8_t *) scid,
                                            sizeof(scid), config);
        if (conn == NULL) {
            DBG_FPRINTF(stderr, "failed to create connection\n");
            return -1;
        }
    }

    struct conn_io *conn_io = malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        DBG_FPRINTF(stderr, "failed to allocate connection IO\n");
        return -1;
    }

    conn_io->sock = sock;
    conn_io->conn = conn;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    if (op_mode == OPMODE_RAW_UDP) {
        ev_io_init(&watcher, recv_cb_udp, conn_io->sock, EV_READ);
    } else {
        ev_io_init(&watcher, recv_cb, conn_io->sock, EV_READ);
        ev_init(&conn_io->timer, timeout_cb);
        conn_io->timer.data = conn_io;
    }

    ev_io_start(loop, &watcher);
    watcher.data = conn_io;

    if (op_mode == OPMODE_RAW_UDP) {
        int magic = 12345678;
        send(conn_io->sock, &magic, sizeof(int), 0);
    } else {
        flush_egress(loop, conn_io);
    }

    ev_loop(loop, 0);

    printf("Exited main loop\n");

    freeaddrinfo(peer);

    quiche_conn_free(conn);

    quiche_config_free(config);

    return 0;
}

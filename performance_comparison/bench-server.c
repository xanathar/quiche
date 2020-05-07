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

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <ev.h>
#include <uthash.h>

#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

//#define TEST_16K

#ifdef TEST_16K
    #define MAX_PACKET_SIZE 16300
    #define DATAGRAM_SIZE 16000
    #define STR_TEST_MODE "16K"
#else
    #define MAX_PACKET_SIZE 1350
    #define DATAGRAM_SIZE 1024
    #define STR_TEST_MODE "1K"
#endif


#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

#define DBG_FPRINTF(...)
#define ERR_FPRINTF fprintf

struct connections {
    int sock;

    struct conn_io *h;
};

struct conn_io {
    ev_timer timer;
    ev_idle idle;
    ev_timer report_timer;

    int sock;

    uint8_t cid[LOCAL_CONN_ID_LEN];

    quiche_conn *conn;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    UT_hash_handle hh;

    int last_dgram_sent;
};

static quiche_config *config = NULL;

static struct connections *conns = NULL;

static void timeout_cb(EV_P_ ev_timer *w, int revents);
static void report_cb(EV_P_ ev_timer *w, int revents);

static void idle_cb(struct ev_loop *loop, ev_idle *w, int revents);

static void free_conn_if_closed(struct ev_loop *loop, struct conn_io *conn_io);

static uint32_t datagram_data[DATAGRAM_SIZE / 4];

typedef enum _OperationMode 
{
    OPMODE_QUIC_DX,
    OPMODE_RAW_UDP
} OperationMode;

static OperationMode op_mode;

static int conn_count = 0;

static bool stuck = false;

static void debug_log(const char *line, void *argp) {
    //if (strlen(line) > 25 && line[25] == '!') {
    if (conn_count > 1) {
        fprintf(stderr, "%s\n", line);
    }
    DBG_FPRINTF(stderr, "%s\n", line);
}

static ssize_t vtotal = 0;
static int vtotalp = 0;

static int qlog_fd;
static void qlog_open(quiche_conn *conn) {
//    char sbuf[800];
//    sprintf(sbuf, "/temp/qlog/client_%u", time(NULL));
//
//    qlog_fd = open(sbuf, O_WRONLY | O_APPEND | O_CREAT, 0666);
// 
//    quiche_conn_set_qlog_fd(conn, qlog_fd, 
//        "bench-client",
//        "bench-client");
}
static void qlog_flush() {
//    fsync(qlog_fd);
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_PACKET_SIZE];
    ssize_t total = 0;
    int totalp = 0;

    while (1) {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out) - 1);

        if (written == QUICHE_ERR_DONE) {
            //printf("done sending, total bytes: %zd, packets: %d, very total bytes: %zd, very total packets: %d\n", total, totalp, vtotal, vtotalp);
            break;
        }

        if (written < 0) {
            ERR_FPRINTF(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        ssize_t sent = sendto(conn_io->sock, out, written, 0,
                              (struct sockaddr *) &conn_io->peer_addr,
                              conn_io->peer_addr_len);
        if (sent != written) {
            perror("failed to send");
            exit(0);
        }

        total += sent;
        vtotal += sent;
        vtotalp++;
        totalp++;

        DBG_FPRINTF(stderr, "sent %zd bytes\n", sent);
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);    
    //printf("... next timeout scheduled in %f seconds; connection is %s\n", t, stuck ? "STUCK" : "ok");
    if (t < __DBL_EPSILON__) {
        printf("Processing timeout in sync... \n");
        quiche_conn_on_timeout(conn_io->conn);
    }
}

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len) {
    memcpy(token, "quiche", sizeof("quiche") - 1);
    memcpy(token + sizeof("quiche") - 1, addr, addr_len);
    memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

    *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len) {
    if ((token_len < sizeof("quiche") - 1) ||
         memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

static struct conn_io *create_conn(uint8_t *odcid, size_t odcid_len) {
    struct conn_io *conn_io = malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        ERR_FPRINTF(stderr, "failed to allocate connection IO\n");
        return NULL;
    }

    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, conn_io->cid, LOCAL_CONN_ID_LEN);
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return NULL;
    }

    quiche_conn *conn;
    
    if (op_mode == OPMODE_QUIC_DX) {
        conn = quiche_accept(conn_io->cid, LOCAL_CONN_ID_LEN,
                             odcid, odcid_len, config);   
        if (conn == NULL) {
            ERR_FPRINTF(stderr, "failed to create connection\n");
            return NULL;
        }
        conn_count += 1;

        if (conn_count > 1) {
            quiche_enable_debug_logging(debug_log, NULL);            
        }
    } else {
        conn = NULL;
    }

    conn_io->sock = conns->sock;
    conn_io->conn = conn;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;
    ev_init(&conn_io->report_timer, report_cb);
    conn_io->report_timer.data = conn_io;
    conn_io->report_timer.repeat = 1.0;
    ev_timer_again(ev_default_loop(0), &conn_io->report_timer);      
    ev_idle_init(&conn_io->idle, idle_cb);
    ev_idle_start(ev_default_loop(0), &conn_io->idle);
    conn_io->idle.data = conn_io;
    conn_io->last_dgram_sent = (conn_count > 1) ? -99 : -1;

    qlog_open(conn);

    DBG_FPRINTF(stderr, "new connection\n");

    return conn_io;
}

static void recv_cb_udp(EV_P_ ev_io *w, int revents) {
    struct conn_io *conn_io = NULL;

    static uint8_t buf[65535];

    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conns->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                DBG_FPRINTF(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        HASH_FIND(hh, conns->h, &peer_addr, peer_addr_len, conn_io);

        if (conn_io == NULL) {
            printf("Client connected\n");

            conn_io = create_conn(NULL, 0);

            if (conn_io != NULL) {
                memcpy(&conn_io->peer_addr, &peer_addr, peer_addr_len);
                conn_io->peer_addr_len = peer_addr_len;
                HASH_ADD(hh, conns->h, peer_addr, peer_addr_len, conn_io);
            }
        }
    }
}


static void recv_cb(EV_P_ ev_io *w, int revents) {
    struct conn_io *tmp, *conn_io = NULL;

    static uint8_t buf[65535];
    static uint8_t out[MAX_PACKET_SIZE];

    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conns->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                DBG_FPRINTF(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            DBG_FPRINTF(stderr, "failed to parse header: %d\n", rc);
            return;
        }

        HASH_FIND(hh, conns->h, dcid, dcid_len, conn_io);

        if (conn_io == NULL) {
            if (!quiche_version_is_supported(version)) {
                DBG_FPRINTF(stderr, "version negotiation\n");

                ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                           dcid, dcid_len,
                                                           out, sizeof(out));

                if (written < 0) {
                    ERR_FPRINTF(stderr, "failed to create vneg packet: %zd\n",
                            written);
                    return;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    return;
                }

                DBG_FPRINTF(stderr, "sent %zd bytes\n", sent);
                return;
            }

            if (token_len == 0) {
                DBG_FPRINTF(stderr, "stateless retry\n");

                mint_token(dcid, dcid_len, &peer_addr, peer_addr_len,
                           token, &token_len);

                ssize_t written = quiche_retry(scid, scid_len,
                                               dcid, dcid_len,
                                               dcid, dcid_len,
                                               token, token_len,
                                               out, sizeof(out));

                if (written < 0) {
                    ERR_FPRINTF(stderr, "failed to create retry packet: %zd\n",
                            written);
                    return;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    return;
                }

                DBG_FPRINTF(stderr, "sent %zd bytes\n", sent);
                return;
            }


            if (!validate_token(token, token_len, &peer_addr, peer_addr_len,
                               odcid, &odcid_len)) {
                ERR_FPRINTF(stderr, "invalid address validation token\n");
                return;
            }

            conn_io = create_conn(odcid, odcid_len);
            if (conn_io == NULL) {
                return;
            }
            memcpy(&conn_io->peer_addr, &peer_addr, peer_addr_len);
            conn_io->peer_addr_len = peer_addr_len;
            HASH_ADD(hh, conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);
        }

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read);

        if (done == QUICHE_ERR_DONE) {
            DBG_FPRINTF(stderr, "done reading\n");
            break;
        }

        if (done < 0) {
            ERR_FPRINTF(stderr, "failed to process packet: %zd\n", done);
            return;
        }

        DBG_FPRINTF(stderr, "recv %zd bytes\n", done);

        if (quiche_conn_is_established(conn_io->conn)) {
            uint64_t s = 0;
            const uint8_t dgram_start_command[] = "DGRAM-START";
            const uint8_t dgram_ping_command[] = "DGRAM-PING";

            quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

            while (quiche_stream_iter_next(readable, &s)) {
                DBG_FPRINTF(stderr, "stream %" PRIu64 " is readable\n", s);

                bool fin = false;
                ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s,
                                                           buf, sizeof(buf),
                                                           &fin);
                if (recv_len < 0) {
                    break;
                }

                if (recv_len > sizeof(dgram_start_command) && 
                    !memcmp(buf, dgram_start_command, 
                            sizeof(dgram_start_command) - 1)) {
                    static const char *resp = "ok\n";
                    quiche_conn_stream_send(conn_io->conn, s, (uint8_t *) resp,
                                            3, false);

                    if (conn_io->last_dgram_sent == -1) 
                        conn_io->last_dgram_sent = 0;
                        
                    DBG_FPRINTF(stderr, "received start of datagrams, sending data\n");
                } else if (recv_len > sizeof(dgram_ping_command) && 
                    !memcmp(buf, dgram_ping_command, 
                            sizeof(dgram_ping_command) - 1)) {
                    DBG_FPRINTF(stderr, "received ping...\n");
                } else {
                    static const char *resp = "byez\n";
                    quiche_conn_stream_send(conn_io->conn, s, (uint8_t *) resp,
                                            5, true);
                    DBG_FPRINTF(stderr, "received end of session, sending byez\n");
                }
            }

            quiche_stream_iter_free(readable);
        }
    }

    HASH_ITER(hh, conns->h, conn_io, tmp) {
        flush_egress(loop, conn_io);
        free_conn_if_closed(loop, conn_io);
    }
}

static void idle_cb(struct ev_loop *loop, ev_idle *w, int revents) {
    struct conn_io *conn_io = w->data;

    if (conn_io->last_dgram_sent < -50) {
        return;
    }

    if (op_mode == OPMODE_RAW_UDP) {
        if (conn_io->last_dgram_sent < 0) {
            conn_io->last_dgram_sent = 0;
            printf("Sending started...\n");
        }

        for(int i = 0; i < 1000; i++) {
            datagram_data[0] = conn_io->last_dgram_sent++;
            sendto(conn_io->sock, (uint8_t *)datagram_data, sizeof(datagram_data), 0,
                   (struct sockaddr *) &conn_io->peer_addr,
                   conn_io->peer_addr_len);            
        }
    }
    else if (op_mode == OPMODE_QUIC_DX) {
        if (conn_io->last_dgram_sent < 0) {
            return;
        }

        int pkt_count = 0;
        ssize_t res = 0;
        while(res >= 0) {
            datagram_data[0] = conn_io->last_dgram_sent;
            res = quiche_conn_datagram_send(conn_io->conn, (uint8_t *)datagram_data, sizeof(datagram_data));
            if (res >= 0) {
                ++pkt_count;
                conn_io->last_dgram_sent+=1;
            }
        } 
        flush_egress(loop, conn_io);
        if (pkt_count == 0 && !stuck) {
            printf("Sender is probably STUCK\n"); 
            stuck = true;
            qlog_flush();
        }
        if (pkt_count > 0 && stuck) {
            printf("Sender now UNSTUCK\n"); 
            stuck = false;
        }

        free_conn_if_closed(loop, conn_io);        
    }


    /* static ssize_t bandwidth_opener_count = 0 * (1 << 20); */



/*    if (bandwidth_opener_count > 0) {
        ssize_t sent = 1;
        while(sent > 0 && bandwidth_opener_count > 0) {
            sent = quiche_conn_stream_send(conn_io->conn, 4, (uint8_t *)datagram_data, sizeof(datagram_data), false);
            if (sent > 0) {
                bandwidth_opener_count -= sent;
            }
            flush_egress(loop, conn_io);
            //printf("  bandwidth opener sent %zd, remaining: %zd\n", sent, bandwidth_opener_count);
        }
        printf("bandwidth opener remaining: %zd\n", bandwidth_opener_count);
        
        return;
    }
*/


}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    printf("Processing timeout ... \n");
    quiche_conn_on_timeout(conn_io->conn);

    DBG_FPRINTF(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    free_conn_if_closed(loop, conn_io);
}

static void free_conn_if_closed(struct ev_loop *loop, struct conn_io *conn_io) {
    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;

        quiche_conn_stats(conn_io->conn, &stats);
        fprintf(stderr, "connection closed, dgrams_sent=%d, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns cwnd=%zu\n",
				conn_io->last_dgram_sent, stats.recv, stats.sent, stats.lost, stats.rtt, stats.cwnd);

        HASH_DELETE(hh, conns->h, conn_io);

        ev_timer_stop(loop, &conn_io->report_timer);
        ev_timer_stop(loop, &conn_io->timer);
        ev_idle_stop(loop, &conn_io->idle);
        quiche_conn_free(conn_io->conn);
        free(conn_io);

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

static void report_cb(EV_P_ ev_timer *w, int revents) {
    static int report_count = 0;
    static int last_time_last_dgram_sent = 0;
    struct conn_io *conn_io = w->data;

    int dgrams_sent = conn_io->last_dgram_sent - last_time_last_dgram_sent;

    printf("\n-=-=-=-| REPORT #%03d |-=-=-=-\n", ++report_count);
    printf("last_dgram_sent : %d\n", conn_io->last_dgram_sent);
    printf("est. dgrams/sec : %d\n", dgrams_sent);
    quiche_conn_print_debug(conn_io->conn);
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");

    last_time_last_dgram_sent = conn_io->last_dgram_sent;

    conn_io->report_timer.repeat = 1.0;
    ev_timer_again(loop, &conn_io->report_timer);    
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

    memset(datagram_data, 0xDE, sizeof(datagram_data));

    //quiche_enable_debug_logging(debug_log, NULL);
    debug_log("", NULL);

    struct addrinfo *local;
    if (getaddrinfo(host, port, &hints, &local) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    if (cmdline_op_mode == NULL) {
        fprintf(stderr, "op_mode not specified: [qdx|rawudp]");
        return -1;
    } else if (0 == strcmp(cmdline_op_mode, "qdx")) {
        printf("Starting in QUIC datagram mode\n");
        op_mode = OPMODE_QUIC_DX;
    } else if (0 == strcmp(cmdline_op_mode, "rawudp")) {
        printf("Starting in UDP mode\n");
        op_mode = OPMODE_RAW_UDP;
    } else {
        fprintf(stderr, "op_mode invalid: must be 'quiche' or 'rawudp'");
        return -1;
    }

    printf("Test mode is %s\n", STR_TEST_MODE);

    int sock = socket(local->ai_family, SOCK_DGRAM, 0);
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

    if (bind(sock, local->ai_addr, local->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }

    if (op_mode == OPMODE_QUIC_DX) {
        config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
        if (config == NULL) {
            DBG_FPRINTF(stderr, "failed to create config\n");
            return -1;
        }

        quiche_config_load_cert_chain_from_pem_file(config, "cert.crt");
        quiche_config_load_priv_key_from_pem_file(config, "cert.key");

        quiche_config_set_application_protos(config,
            (uint8_t *) "\x0dtest-dgram-01", 14);

        quiche_config_set_max_idle_timeout(config, 5000000);
        quiche_config_set_max_packet_size(config, MAX_PACKET_SIZE);
        quiche_config_set_initial_max_data(config, 10000000);
        quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
        quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
        quiche_config_set_initial_max_streams_bidi(config, 100);
        quiche_config_set_cc_algorithm(config, QUICHE_CC_CUBIC);
        quiche_config_set_max_datagram_frame_size(config, 65535);
        quiche_config_set_datagram_send_queue_size(config, 1000);
    }

    struct connections c;
    c.sock = sock;
    c.h = NULL;

    conns = &c;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    if (op_mode == OPMODE_QUIC_DX) {
        ev_io_init(&watcher, recv_cb, sock, EV_READ);
    } else {
        ev_io_init(&watcher, recv_cb_udp, sock, EV_READ);
    }
    ev_io_start(loop, &watcher);
    watcher.data = &c;

    ev_loop(loop, 0);

    freeaddrinfo(local);

    if (op_mode == OPMODE_QUIC_DX) {
        quiche_config_free(config);
    }

    return 0;
}

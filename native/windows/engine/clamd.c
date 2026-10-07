/* One deadline covers VERSION, content transfer and verdict. No filesystem paths. */
#include "engine.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
typedef SOCKET ao_socket;
#define AO_BAD_SOCKET INVALID_SOCKET
#define ao_close closesocket
static int ao_socket_error(void) { return WSAGetLastError(); }
static int ao_would_block(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
static uint64_t ao_clock(void) { return GetTickCount64(); }
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
typedef int ao_socket;
#define AO_BAD_SOCKET (-1)
#define ao_close close
static int ao_socket_error(void) { return errno; }
static int ao_would_block(int e) { return e == EAGAIN || e == EWOULDBLOCK || e == EINPROGRESS || e == EINTR; }
static uint64_t ao_clock(void) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
#endif

struct request { uint64_t deadline; ao_cancel_fn cancelled; void *context;
    ao_peer_fn verifier; void *peer_context; int peer_rejected; };
static int active(struct request *r) {
    return (!r->cancelled || !r->cancelled(r->context)) && ao_clock() < r->deadline;
}
static int ready(ao_socket s, int writing, struct request *r) {
    while (active(r)) {
        fd_set reads, writes, errors;
        struct timeval slice = {0, 50000};
        int result;
        FD_ZERO(&reads); FD_ZERO(&writes); FD_ZERO(&errors);
        FD_SET(s, writing ? &writes : &reads); FD_SET(s, &errors);
        result = select((int)s + 1, &reads, &writes, &errors, &slice);
        if (result > 0) return active(r) && !FD_ISSET(s, &errors);
        if (result < 0 && !ao_would_block(ao_socket_error())) return 0;
    }
    return 0;
}
static ao_socket connect_local(unsigned short port, struct request *r) {
    struct sockaddr_in address;
    ao_socket s;
    int connected, error = 0;
#ifdef _WIN32
    u_long nonblocking = 1;
    int length = sizeof(error);
#else
    socklen_t length = sizeof(error);
#endif
    if (!active(r)) return AO_BAD_SOCKET;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == AO_BAD_SOCKET) return s;
#ifdef _WIN32
    if (ioctlsocket(s, FIONBIO, &nonblocking)) goto failed;
#else
    if (s >= FD_SETSIZE || fcntl(s, F_SETFL, O_NONBLOCK) < 0) goto failed;
#endif
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET; address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connected = connect(s, (const struct sockaddr *)&address, sizeof(address));
    if (connected && (!ao_would_block(ao_socket_error()) || !ready(s, 1, r))) goto failed;
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&error, &length) || error) goto failed;
    if (r->verifier && !r->verifier((uintptr_t)s, r->peer_context)) {
        r->peer_rejected = 1; goto failed;
    }
    if (!active(r)) goto failed;
    return s;
failed:
    ao_close(s); return AO_BAD_SOCKET;
}
static int send_all(ao_socket s, const void *buffer, size_t size, struct request *r) {
    const char *bytes = buffer;
    while (size && active(r)) {
        int sent;
        if (!ready(s, 1, r)) return 0;
#ifdef _WIN32
        sent = send(s, bytes, (int)size, 0);
#else
        sent = (int)send(s, bytes, size, MSG_NOSIGNAL);
#endif
        if (sent < 0 && ao_would_block(ao_socket_error())) continue;
        if (sent <= 0) return 0;
        bytes += sent; size -= (size_t)sent;
    }
    return !size && active(r);
}
static int receive_reply(ao_socket s, char reply[AO_REPLY_LIMIT], size_t *size, struct request *r) {
    size_t used = 0;
    while (used < AO_REPLY_LIMIT - 1 && active(r)) {
        int count;
        char *end;
        if (!ready(s, 0, r)) return 0;
        count = recv(s, reply + used, (int)(AO_REPLY_LIMIT - 1 - used), 0);
        if (count < 0 && ao_would_block(ao_socket_error())) continue;
        if (count <= 0) return 0;
        end = memchr(reply + used, 0, (size_t)count);
        used += (size_t)count;
        if (end) {
            if (end != reply + used - 1) return 0;
            *size = used - 1; return 1;
        }
    }
    return 0;
}

static struct ao_outcome scan_impl(const unsigned char *data, size_t size, unsigned short port,
                              unsigned timeout_ms, ao_cancel_fn cancelled, void *context, ao_peer_fn verifier, void *peer_context) {
    struct ao_outcome outcome = {AO_UNKNOWN, 0, 0, "", "engine unavailable, cancelled or timed out"};
    struct request request = {0};
    ao_socket s = AO_BAD_SOCKET;
    char reply[AO_REPLY_LIMIT];
    size_t reply_size = 0, offset;
#ifdef _WIN32
    WSADATA startup;
    if (WSAStartup(MAKEWORD(2, 2), &startup)) return outcome;
#endif
    request.verifier = verifier; request.peer_context = peer_context;
    request.deadline = ao_clock() + timeout_ms; request.cancelled = cancelled; request.context = context;
    if ((!data && size) || size > AO_MAX_FILE_BYTES || !port || !timeout_ms || timeout_ms > 30000) {
        strcpy(outcome.detail, "input exceeds native scan limits"); goto done;
    }
    s = connect_local(port, &request);
    if (s == AO_BAD_SOCKET || !send_all(s, "zVERSION", 9, &request) ||
        !receive_reply(s, reply, &reply_size, &request)) goto done;
    if (reply_size < 8 || reply_size > 507 || memcmp(reply, "ClamAV ", 7)) goto done;
    outcome.database_current = ao_database_current(reply, time(NULL));
    outcome.database_generation = outcome.database_current ? ao_database_generation(reply) : 0;
    if (outcome.database_current && !outcome.database_generation) outcome.database_current = 0;
    ao_close(s); s = connect_local(port, &request);
    if (s == AO_BAD_SOCKET || !send_all(s, "zINSTREAM", 10, &request)) goto done;
    for (offset = 0; offset < size;) {
        size_t amount = size - offset > 65536 ? 65536 : size - offset;
        uint32_t frame = htonl((uint32_t)amount);
        if (!send_all(s, &frame, sizeof(frame), &request) ||
            !send_all(s, data + offset, amount, &request)) goto done;
        offset += amount;
    }
    {
        uint32_t end = 0;
        if (!send_all(s, &end, sizeof(end), &request) || !receive_reply(s, reply, &reply_size, &request)) goto done;
    }
    outcome.result = ao_parse_reply(reply, reply_size, outcome.name);
    if (outcome.result == AO_CLEAR && !outcome.database_current) {
        outcome.result = AO_UNKNOWN;
        strcpy(outcome.detail, "database freshness is stale, unknown or in the future");
    } else if (outcome.result == AO_REVIEW) strcpy(outcome.detail, "heuristic or incomplete coverage; no automatic block");
    else if (outcome.result == AO_UNKNOWN) strcpy(outcome.detail, "invalid or failed ClamD verdict");
    else outcome.detail[0] = 0;
done:
    if (request.peer_rejected) strcpy(outcome.detail, "engine peer identity rejected; no verdict accepted");
    if (!active(&request)) {
        outcome.result = AO_UNKNOWN;
        strcpy(outcome.detail, "scan cancelled or deadline expired");
    }
    if (s != AO_BAD_SOCKET) ao_close(s);
#ifdef _WIN32
    WSACleanup();
#endif
    return outcome;
}

uint64_t ao_clam_generation_verified(unsigned short port, unsigned timeout_ms,
    ao_cancel_fn cancelled, void *context, ao_peer_fn verifier, void *peer_context, int *database_current) {
    struct request request = {0};
    ao_socket s = AO_BAD_SOCKET;
    char reply[AO_REPLY_LIMIT];
    size_t reply_size = 0;
    uint64_t generation = 0;
#ifdef _WIN32
    WSADATA startup;
    if (WSAStartup(MAKEWORD(2, 2), &startup)) return 0;
#endif
    if (database_current) *database_current = 0;
    if (!verifier || !port || !timeout_ms || timeout_ms > 30000) goto done;
    request.verifier = verifier;
    request.peer_context = peer_context;
    request.deadline = ao_clock() + timeout_ms;
    request.cancelled = cancelled;
    request.context = context;
    s = connect_local(port, &request);
    if (s == AO_BAD_SOCKET || !send_all(s, "zVERSION", 9, &request) ||
        !receive_reply(s, reply, &reply_size, &request)) goto done;
    if (reply_size < 8 || reply_size > 507 || memcmp(reply, "ClamAV ", 7)) goto done;
    if (ao_database_current(reply, time(NULL))) {
        generation = ao_database_generation(reply);
        if (generation && database_current) *database_current = 1;
    }
done:
    if (request.peer_rejected || !active(&request)) {
        generation = 0;
        if (database_current) *database_current = 0;
    }
    if (s != AO_BAD_SOCKET) ao_close(s);
#ifdef _WIN32
    WSACleanup();
#endif
    return generation;
}

/* Deliberately unauthenticated diagnostic/test entry point; the broker never uses it. */
struct ao_outcome ao_clam_scan(const unsigned char *data, size_t size, unsigned short port,
                              unsigned timeout_ms, ao_cancel_fn cancelled, void *context) {
    return scan_impl(data, size, port, timeout_ms, cancelled, context, NULL, NULL);
}
struct ao_outcome ao_clam_scan_verified(const unsigned char *data, size_t size, unsigned short port,
    unsigned timeout_ms, ao_cancel_fn cancelled, void *context, ao_peer_fn verifier, void *peer_context) {
    struct ao_outcome rejected = {AO_UNKNOWN, 0, 0, "", "engine peer verifier required"};
    if (!verifier) return rejected;
    return scan_impl(data, size, port, timeout_ms, cancelled, context, verifier, peer_context);
}

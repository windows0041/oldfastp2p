#include "gateway.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Binds one probe listener. family is AF_INET or AF_INET6; each family owns an
 * independent set of ports (SPEC §2) so a v4-only gateway keeps today's exact
 * behaviour and a dual-stack gateway answers probes on both. */
static int bound(const char *ip, unsigned port, int udp, int family) {
    int fd = socket(family, (udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* Every family gets its own sockets, so the v6 listeners must not claim the
     * v4 port space as well (Linux defaults bindv6only=0). */
    if (family == AF_INET6 &&
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))) {
        close(fd);
        return -1;
    }
    if (udp && family == AF_INET && setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one))) {
        close(fd);
        return -1;
    }
    /* Preserve the "reply from the address that was actually hit" semantics:
     * the destination seen on receive becomes the source on send. */
    if (udp && family == AF_INET6 &&
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one))) {
        close(fd);
        return -1;
    }
    if (family == AF_INET) {
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
        if (inet_pton(AF_INET, ip, &a.sin_addr) != 1 ||
            bind(fd, (struct sockaddr *)&a, sizeof(a)) || (!udp && listen(fd, 64))) {
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((uint16_t)port)};
        if (inet_pton(AF_INET6, ip, &a.sin6_addr) != 1 ||
            bind(fd, (struct sockaddr *)&a, sizeof(a)) || (!udp && listen(fd, 64))) {
            close(fd);
            return -1;
        }
    }
    return fd;
}
static void close_set(int *fds, int count) {
    for (int i = 0; i < count; ++i)
        if (fds[i] >= 0) {
            close(fds[i]);
            fds[i] = -1;
        }
}
void gw_nat_stop(struct nat_state *s) {
    close_set(s->udp, 4);
    close_set(s->tcp, 2);
    close_set(s->udp6, 4);
    close_set(s->tcp6, 2);
    for (int i = 0; i < GW_MAX_PROBES; ++i)
        if (s->probes[i].fd >= 0) {
            close(s->probes[i].fd);
            s->probes[i].fd = -1;
        }
}
int gw_nat_start(struct nat_state *s, const char *ip, const char *bind6) {
    memset(s, 0, sizeof(*s));
    for (int i = 0; i < 4; ++i)
        s->udp[i] = -1;
    for (int i = 0; i < 2; ++i)
        s->tcp[i] = -1;
    for (int i = 0; i < 4; ++i)
        s->udp6[i] = -1;
    for (int i = 0; i < 2; ++i)
        s->tcp6[i] = -1;
    for (int i = 0; i < GW_MAX_PROBES; ++i)
        s->probes[i].fd = -1;
    int has_v6 = bind6 && *bind6;
    for (int i = 0; i < 4; ++i)
        if ((s->udp[i] = bound(ip, 27180 + (unsigned)i, 1, AF_INET)) < 0)
            goto error;
    for (int i = 0; i < 2; ++i)
        if ((s->tcp[i] = bound(ip, 27180 + (unsigned)i, 0, AF_INET)) < 0)
            goto error;
    if (has_v6) {
        for (int i = 0; i < 4; ++i)
            if ((s->udp6[i] = bound(bind6, 27180 + (unsigned)i, 1, AF_INET6)) < 0)
                goto error;
        for (int i = 0; i < 2; ++i)
            if ((s->tcp6[i] = bound(bind6, 27180 + (unsigned)i, 0, AF_INET6)) < 0)
                goto error;
    }
    return 0;
error:
    gw_nat_stop(s);
    return -1;
}
/* The reply shape is identical for both families; only the address handling and
 * the pktinfo control message differ. */
static void udp_answer(struct nat_state *s, int fd, int family, int index) {
    for (int attempt = 0; attempt < 128; ++attempt) {
        unsigned char packet[4096];
        struct sockaddr_storage peer;
        union {
            struct cmsghdr alignment;
            unsigned char v4[CMSG_SPACE(sizeof(struct in_pktinfo))];
            unsigned char v6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        } control;
        struct iovec input = {.iov_base = packet, .iov_len = sizeof(packet)};
        /* The union is the size of the larger (v6) control message, so receiving
         * never truncates the pktinfo cmsg on either family. */
        struct msghdr message = {.msg_name = &peer, .msg_namelen = sizeof(peer),
            .msg_iov = &input, .msg_iovlen = 1, .msg_control = control.v4,
            .msg_controllen = sizeof(control)};
        ssize_t n = recvmsg(fd, &message, 0);
        if (n < 0)
            break;
        int mapped = 0;
        if (family == AF_INET) {
            if (message.msg_namelen != sizeof(struct sockaddr_in))
                continue;
        } else {
            if (message.msg_namelen != sizeof(struct sockaddr_in6))
                continue;
            /* A v6-only listener should never see v4 traffic, but a mapped frame
             * must not be answered as if it were genuine v6. */
            mapped = IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&peer)->sin6_addr);
        }
        if (mapped)
            continue;
        union {
            struct in_addr v4;
            struct in6_addr v6;
        } local = {0};
        int have_local = 0;
        for (struct cmsghdr *part = CMSG_FIRSTHDR(&message); part;
             part = CMSG_NXTHDR(&message, part)) {
            if (family == AF_INET && part->cmsg_level == IPPROTO_IP &&
                part->cmsg_type == IP_PKTINFO &&
                part->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
                struct in_pktinfo info;
                memcpy(&info, CMSG_DATA(part), sizeof(info));
                local.v4 = info.ipi_addr;
                have_local = local.v4.s_addr != 0;
            } else if (family == AF_INET6 && part->cmsg_level == IPPROTO_IPV6 &&
                       part->cmsg_type == IPV6_PKTINFO &&
                       part->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
                struct in6_pktinfo info;
                memcpy(&info, CMSG_DATA(part), sizeof(info));
                local.v6 = info.ipi6_addr;
                have_local = !IN6_IS_ADDR_UNSPECIFIED(&local.v6);
            }
        }
        /* Bound aggregate work and amplification; only answer the observed IP. */
        if (++s->packets > 10000 || n < 8 || !have_local ||
            (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
            ((struct sockaddr *)&peer)->sa_family != (sa_family_t)family ||
            gw_u32(packet) != (uint32_t)(n - 8) || gw_u16(packet + 4) != 2 ||
            gw_u16(packet + 6) > 2)
            continue;
        json_object *request = NULL;
        if (n != 12 || memcmp(packet + 8, "null", 4)) {
            request = gw_json(packet + 8, (size_t)n - 8);
            if (!request || !json_object_is_type(request, json_type_object)) {
                if (request)
                    json_object_put(request);
                continue;
            }
        }
        unsigned sub = gw_u16(packet + 6);
        /* Inbound-filtering probe. A client that already knows its mapping asks
         * for an answer from a *different local port*: a NAT that keeps the
         * filter keyed on the exact port (port-restricted) drops it, while an
         * address-restricted or full-cone NAT lets it through. This is the
         * change-port half of the classic STUN CHANGE-REQUEST test, done against
         * the gateway instead of an external server. */
        if (sub == 2) {
            uint64_t port = gw_integer(request, "port");
            uint64_t nonce = gw_integer(request, "nonce");
            if (request)
                json_object_put(request);
            if (!port || port > 65535)
                continue;
            if (family == AF_INET)
                ((struct sockaddr_in *)&peer)->sin_port = htons((uint16_t)port);
            else
                ((struct sockaddr_in6 *)&peer)->sin6_port = htons((uint16_t)port);
            /* Any sibling probe port differs from the one the request arrived on;
             * rotating keeps a single rule from being pinned to one port. */
            int sibling = -1;
            for (int step = 1; step < 4 && sibling < 0; ++step) {
                int candidate = (index + step) % 4;
                int alt = family == AF_INET ? s->udp[candidate] : s->udp6[candidate];
                if (candidate != index && alt >= 0)
                    sibling = alt;
            }
            if (sibling < 0)
                continue;
            char body[96];
            int used = snprintf(body, sizeof(body), "{\"nonce\":%llu}", (unsigned long long)nonce);
            if (used <= 0 || (size_t)used >= sizeof(body))
                continue;
            unsigned char marker[128];
            gw_put32(marker, (uint32_t)used);
            gw_put16(marker + 4, 2);
            gw_put16(marker + 6, 2);
            memcpy(marker + 8, body, (size_t)used);
            union {
                struct cmsghdr alignment;
                unsigned char v4[CMSG_SPACE(sizeof(struct in_pktinfo))];
                unsigned char v6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
            } alt_control;
            memset(&alt_control, 0, sizeof(alt_control));
            struct iovec alt_output = {.iov_base = marker, .iov_len = (size_t)used + 8};
            struct msghdr alt = {.msg_name = &peer,
                .msg_namelen = family == AF_INET ? sizeof(struct sockaddr_in)
                                                 : sizeof(struct sockaddr_in6),
                .msg_iov = &alt_output, .msg_iovlen = 1, .msg_control = alt_control.v4,
                .msg_controllen = family == AF_INET ? CMSG_SPACE(sizeof(struct in_pktinfo))
                                                    : CMSG_SPACE(sizeof(struct in6_pktinfo))};
            struct cmsghdr *alt_part = CMSG_FIRSTHDR(&alt);
            if (family == AF_INET) {
                alt_part->cmsg_level = IPPROTO_IP; alt_part->cmsg_type = IP_PKTINFO;
                alt_part->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
                struct in_pktinfo info = {.ipi_spec_dst = local.v4};
                memcpy(CMSG_DATA(alt_part), &info, sizeof(info));
            } else {
                alt_part->cmsg_level = IPPROTO_IPV6; alt_part->cmsg_type = IPV6_PKTINFO;
                alt_part->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
                struct in6_pktinfo info = {.ipi6_addr = local.v6};
                memcpy(CMSG_DATA(alt_part), &info, sizeof(info));
            }
            sendmsg(sibling, &alt, MSG_NOSIGNAL);
            continue;
        }
        if (sub == 1) {
            uint64_t port = gw_integer(request, "echoPort");
            if (!port || port > 65535) {
                if (request)
                    json_object_put(request);
                continue;
            }
            if (family == AF_INET)
                ((struct sockaddr_in *)&peer)->sin_port = htons((uint16_t)port);
            else
                ((struct sockaddr_in6 *)&peer)->sin6_port = htons((uint16_t)port);
        }
        if (request)
            json_object_put(request);
        char ip[INET6_ADDRSTRLEN];
        if (family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&peer)->sin_addr, ip, sizeof(ip));
        else
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&peer)->sin6_addr, ip, sizeof(ip));
        json_object *j = json_object_new_object();
        /* SPEC §2: field names are unchanged; "IP" now means the observed source
         * address of either family, always bracket-free canonical text. */
        gw_js(j, "IP", ip);
        gw_ju(j, "port", family == AF_INET ? ntohs(((struct sockaddr_in *)&peer)->sin_port)
                                           : ntohs(((struct sockaddr_in6 *)&peer)->sin6_port));
        gw_ju(j, "isPublicIP", 0);
        const char *text = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
        size_t length = strlen(text);
        unsigned char response[256];
        /* The reply carries a fixed shape today, but the buffer is what enforces it. */
        if (length > sizeof(response) - 8) {
            json_object_put(j);
            continue;
        }
        gw_put32(response, (uint32_t)length);
        gw_put16(response + 4, 2);
        gw_put16(response + 6, (uint16_t)sub);
        memcpy(response + 8, text, length);
        /* Preserve the destination address as reply source on wildcard listeners. */
        memset(&control, 0, sizeof(control));
        struct iovec output = {.iov_base = response, .iov_len = length + 8};
        message = (struct msghdr){.msg_name = &peer,
            .msg_namelen = family == AF_INET ? sizeof(struct sockaddr_in)
                                             : sizeof(struct sockaddr_in6),
            .msg_iov = &output, .msg_iovlen = 1, .msg_control = control.v4,
            .msg_controllen = family == AF_INET ? CMSG_SPACE(sizeof(struct in_pktinfo))
                                                : CMSG_SPACE(sizeof(struct in6_pktinfo))};
        struct cmsghdr *part = CMSG_FIRSTHDR(&message);
        if (family == AF_INET) {
            part->cmsg_level = IPPROTO_IP; part->cmsg_type = IP_PKTINFO;
            part->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo info = {.ipi_spec_dst = local.v4};
            memcpy(CMSG_DATA(part), &info, sizeof(info));
        } else {
            part->cmsg_level = IPPROTO_IPV6; part->cmsg_type = IPV6_PKTINFO;
            part->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            struct in6_pktinfo info = {.ipi6_addr = local.v6};
            memcpy(CMSG_DATA(part), &info, sizeof(info));
        }
        sendmsg(fd, &message, MSG_NOSIGNAL);
        json_object_put(j);
    }
}
/* Accepts on one family's TCP probe listeners. */
static void tcp_accept(struct nat_state *s, int *listeners, uint64_t now) {
    for (int i = 0; i < 2; ++i)
        for (int attempt = 0; attempt < 32; ++attempt) {
            struct sockaddr_storage peer;
            socklen_t n = sizeof(peer);
            int fd = accept4(listeners[i], (struct sockaddr *)&peer, &n,
                             SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0)
                break;
            int slot = 0;
            while (slot < GW_MAX_PROBES && s->probes[slot].fd >= 0)
                ++slot;
            if (slot == GW_MAX_PROBES ||
                (peer.ss_family != AF_INET && peer.ss_family != AF_INET6)) {
                close(fd);
                continue;
            }
            s->probes[slot] = (struct probe){.fd = fd, .peer = peer, .peer_length = n,
                                             .deadline = now + 5000};
        }
}
void gw_nat_step(struct nat_state *s) {
    uint64_t now = gw_mono_ms();
    if (s->second != now / 1000) {
        s->second = now / 1000;
        s->packets = 0;
    }
    for (int i = 0; i < 4; ++i) {
        if (s->udp[i] >= 0)
            udp_answer(s, s->udp[i], AF_INET, i);
        if (s->udp6[i] >= 0)
            udp_answer(s, s->udp6[i], AF_INET6, i);
    }
    tcp_accept(s, s->tcp, now);
    tcp_accept(s, s->tcp6, now);
    for (int i = 0; i < GW_MAX_PROBES; ++i) {
        struct probe *p = &s->probes[i];
        if (p->fd < 0)
            continue;
        int failed = now > p->deadline;
        if (!failed && p->length == p->offset) {
            unsigned char data[1024];
            ssize_t n = recv(p->fd, data, sizeof(data), 0);
            if (n > 0) {
                p->offset = 0;
                int written;
                if (p->peer.ss_family == AF_INET6) {
                    /* SPEC §3 probeV3: an IPv6 echo line is bracketed so the
                     * address/port boundary is unambiguous. */
                    char ip[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&p->peer)->sin6_addr, ip,
                              sizeof(ip));
                    written = snprintf(p->output, sizeof(p->output), "[%s]:%u%s", ip,
                                       ntohs(((struct sockaddr_in6 *)&p->peer)->sin6_port),
                                       data[0] == '2' ? "\n" : "");
                } else {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((struct sockaddr_in *)&p->peer)->sin_addr, ip,
                              sizeof(ip));
                    /* snprintf reports what it would have written; the buffer is the limit. */
                    written = snprintf(p->output, sizeof(p->output), "%s:%u%s", ip,
                                       ntohs(((struct sockaddr_in *)&p->peer)->sin_port),
                                       data[0] == '2' ? "\n" : "");
                }
                p->length = written > 0 && (size_t)written < sizeof(p->output) ? (size_t)written
                                                                             : sizeof(p->output) - 1;
                p->deadline = now + 5000;
            } else if (n == 0 ||
                       (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
                failed = 1;
        }
        if (!failed && p->offset < p->length) {
            ssize_t n = send(p->fd, p->output + p->offset, p->length - p->offset, MSG_NOSIGNAL);
            if (n > 0)
                p->offset += (size_t)n;
            else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                failed = 1;
        }
        if (failed) {
            close(p->fd);
            p->fd = -1;
        }
    }
}

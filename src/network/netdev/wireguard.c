/***
    This file is part of systemd.

    Copyright 2016-2017 Jörg Thalheim <joerg@thalheim.io>
    Copyright 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>.

    systemd is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.

    systemd is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/ioctl.h>
#include <net/if.h>

#include "alloc-util.h"
#include "parse-util.h"
#include "fd-util.h"
#include "strv.h"
#include "hexdecoct.h"
#include "string-util.h"
#include "wireguard.h"
#include "networkd-link.h"
#include "networkd-util.h"
#include "networkd-manager.h"

#define WG_SET_DEVICE (SIOCDEVPRIVATE + 1)
#define MAX_CONCURRENT_QUERIES 2048

static void resolve_endpoints(NetDev *netdev);

static WireguardPeer *wireguard_peer_new(Wireguard *w, unsigned section) {
        WireguardPeer *peer;

        assert(w);

        if (w->last_peer_section == section && w->peers)
                return w->peers;

        peer = new0(WireguardPeer, 1);
        if (!peer)
                return NULL;
        peer->fields.persistent_keepalive_interval = (uint16_t)-1;

        LIST_PREPEND(peers, w->peers, peer);
        w->allocation_size += sizeof(struct wgpeer);
        w->last_peer_section = section;
        w->dev.num_peers++;

        return peer;
}

static int update_wireguard_config(NetDev *netdev) {
        _cleanup_close_ int fd = -1;
        _cleanup_free_ void *data = NULL;
        uint8_t *pos = NULL;
        struct ifreq ifreq = {};
        Wireguard *w;
        WireguardPeer *peer;
        WireguardIpmask *mask;

        assert(netdev);

        w = WIREGUARD(netdev);

        assert(w);

        fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_netdev_error_errno(netdev, errno, "Failed to open AF_INET to configure wireguard: %m");

        strncpy(ifreq.ifr_name, netdev->ifname, IFNAMSIZ);
        data = new0(char, w->allocation_size);
        if (!data)
                return log_oom();

        pos = data;
        memcpy(pos, &w->dev, sizeof(struct wgdevice));
        pos = pos + sizeof(struct wgdevice);
        LIST_FOREACH(peers, peer, w->peers) {
                memcpy(pos, &peer->fields, sizeof(struct wgpeer));
                pos = pos + sizeof(struct wgpeer);

                LIST_FOREACH(ipmasks, mask, peer->ipmasks) {
                        memcpy(pos, &mask->fields, sizeof(struct wgipmask)),
                        pos = pos + sizeof(struct wgipmask);
                }
        }
        assert((size_t)((char*)pos - (char*)data) == w->allocation_size);
        ifreq.ifr_data = data;

        if (ioctl(fd, WG_SET_DEVICE, &ifreq) == -1)
                return log_netdev_error_errno(netdev, errno, "Unable configure wireguard device: %m");

        return 0;
}

static void endpoint_free(WireguardEndpoint *e) {
        assert(e);
        free(e->host);
        free(e->port);
        free(e);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(WireguardEndpoint*, endpoint_free);

static int on_resolve_retry(sd_event_source *s, usec_t usec, void *userdata) {
        NetDev *netdev = userdata;
        Wireguard *w;

        assert(netdev);
        w = WIREGUARD(netdev);
        assert(w);

        w->resolve_retry_event_source = sd_event_source_unref(w->resolve_retry_event_source);

        w->unresolved_endpoints = w->failed_endpoints;
        w->n_unresolved_endpoints = w->n_failed_endpoints;
        w->failed_endpoints = NULL;
        w->n_failed_endpoints = 0;

        resolve_endpoints(netdev);

        return 0;
}

static int wireguard_resolve_handler(sd_resolve_query *q,
                                     int ret,
                                     const struct addrinfo *ai,
                                     void *userdata) {
        NetDev *netdev;
        Wireguard *w;
        _cleanup_(endpoint_freep) WireguardEndpoint *e;
        int r;

        assert(userdata);
        e = userdata;
        netdev = e->netdev;

        assert(netdev);
        w = WIREGUARD(netdev);
        assert(w);

        LIST_REMOVE(endpoints, w->unresolved_endpoints, e);
        w->n_unresolved_endpoints--;

        if (ret != 0) {
                log_netdev_error(netdev, "Failed to resolve host '%s:%s': %s", e->host, e->port, gai_strerror(ret));
                LIST_PREPEND(endpoints, w->failed_endpoints, e);
                w->n_failed_endpoints++;
                e = NULL;
        } else if ((ai->ai_family == AF_INET && ai->ai_addrlen == sizeof(struct sockaddr_in)) ||
                        (ai->ai_family == AF_INET6 && ai->ai_addrlen == sizeof(struct sockaddr_in6)))
                memcpy(&e->peer->fields.endpoint, ai->ai_addr, ai->ai_addrlen);
        else
                log_netdev_error(netdev, "Neither IPv4 nor IPv6 address found for peer endpoint: %s:%s", e->host, e->port);

        if (w->n_unresolved_endpoints && w->n_unresolved_endpoints % MAX_CONCURRENT_QUERIES == 0)
                resolve_endpoints(netdev);
        else if (!w->n_unresolved_endpoints) {
                update_wireguard_config(netdev);
                if (w->failed_endpoints) {
                        w->retries++;
                        r = sd_event_add_time(netdev->manager->event,
                                              &w->resolve_retry_event_source,
                                              CLOCK_MONOTONIC,
                                              /* cap at ~25s */
                                              now(CLOCK_MONOTONIC) + (2 << MAX(w->retries, (unsigned)7)) * 100 * USEC_PER_MSEC,
                                              0,
                                              on_resolve_retry,
                                              netdev);
                        if (r < 0)
                                log_netdev_warning_errno(netdev, r, "Could not arm resolve retry handler: %m");
                }
        }

        return 0;
}

static void resolve_endpoints(NetDev *netdev) {
        int r, i = 0;
        Wireguard *w;
        WireguardEndpoint *endpoint;
        static const struct addrinfo hints = {
                .ai_family = AF_UNSPEC,
                .ai_socktype = SOCK_DGRAM,
                .ai_protocol = IPPROTO_UDP
        };

        assert(netdev);
        w = WIREGUARD(netdev);
        assert(w);

        LIST_FOREACH(endpoints, endpoint, w->unresolved_endpoints) {
                if (++i >= MAX_CONCURRENT_QUERIES)
                        break;

                endpoint->netdev = netdev;
                r = sd_resolve_getaddrinfo(netdev->manager->resolve,
                                           &w->resolve_query,
                                           endpoint->host,
                                           endpoint->port,
                                           &hints,
                                           wireguard_resolve_handler,
                                           endpoint);

                if (r < 0)
                        log_netdev_error_errno(netdev, r, "Failed create resolver: %m");
        }
}


static int netdev_wireguard_post_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Wireguard *w;

        assert(netdev);
        w = WIREGUARD(netdev);
        assert(w);

        resolve_endpoints(netdev);
        return 0;
}

int config_parse_wireguard_listen_port(const char *unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata) {
        Wireguard *w;
        uint16_t port = 0;
        int r;

        assert(rvalue);
        assert(data);

        w = WIREGUARD(data);
        assert(w);

        if (!streq(rvalue, "auto")) {
                r = ip_port_from_string(rvalue, &port);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid port specification, ignoring assignment: %s", rvalue);
        }

        w->dev.port = port;

        return 0;
}

static int parse_wireguard_key(const char *unit,
                               const char *filename,
                               unsigned line,
                               const char *section,
                               unsigned section_line,
                               const char *lvalue,
                               int ltype,
                               const char *rvalue,
                               void *data,
                               void *userdata) {
        _cleanup_free_ void *key = NULL;
        size_t len;
        int r;

        assert(filename);
        assert(rvalue);
        assert(userdata);

        r = unbase64mem(rvalue, strlen(rvalue), &key, &len);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Could not parse wireguard key \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }
        if (WG_KEY_LEN != len) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Wireguard key is too short, ignoring assignment: %s", rvalue);
                return 0;
        }

        memcpy(userdata, key, WG_KEY_LEN);
        return true;
}

int config_parse_wireguard_private_key(const char *unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata) {
        Wireguard *w;

        assert(data);

        w = WIREGUARD(data);

        assert(w);

        w->dev.flags &= ~WGDEVICE_REMOVE_PRIVATE_KEY;

        return parse_wireguard_key(unit,
                                   filename,
                                   line,
                                   section,
                                   section_line,
                                   lvalue,
                                   ltype,
                                   rvalue,
                                   data,
                                   &w->dev.private_key);

}

int config_parse_wireguard_preshared_key(const char *unit,
                                         const char *filename,
                                         unsigned line,
                                         const char *section,
                                         unsigned section_line,
                                         const char *lvalue,
                                         int ltype,
                                         const char *rvalue,
                                         void *data,
                                         void *userdata) {
        Wireguard *w;
        WireguardPeer *peer;

        assert(data);

        w = WIREGUARD(data);

        assert(w);

        w->dev.flags &= ~WGPEER_REMOVE_PRESHARED_KEY;

        peer = wireguard_peer_new(w, section_line);
        if (!peer)
                return log_oom();

        return parse_wireguard_key(unit,
                                   filename,
                                   line,
                                   section,
                                   section_line,
                                   lvalue,
                                   ltype,
                                   rvalue,
                                   data,
                                   peer->fields.preshared_key);
}


int config_parse_wireguard_public_key(const char *unit,
                                      const char *filename,
                                      unsigned line,
                                      const char *section,
                                      unsigned section_line,
                                      const char *lvalue,
                                      int ltype,
                                      const char *rvalue,
                                      void *data,
                                      void *userdata) {
        Wireguard *w;
        WireguardPeer *peer;

        assert(data);

        w = WIREGUARD(data);

        assert(w);

        peer = wireguard_peer_new(w, section_line);
        if (!peer)
                return log_oom();

        return parse_wireguard_key(unit,
                                   filename,
                                   line,
                                   section,
                                   section_line,
                                   lvalue,
                                   ltype,
                                   rvalue,
                                   data,
                                   peer->fields.public_key);
}

int config_parse_wireguard_allowed_ips(const char *unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata) {
        union in_addr_union addr;
        unsigned char prefixlen;
        int r, family;
        Wireguard *w;
        WireguardPeer *peer;
        WireguardIpmask *ipmask;

        assert(rvalue);
        assert(data);

        w = WIREGUARD(data);

        peer = wireguard_peer_new(w, section_line);
        if (!peer)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&rvalue, &word, ",", 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to split allowed ips \"%s\" option: %m", rvalue);
                        break;
                }

                r = parse_address_and_prefixlen(word, &family, &addr, &prefixlen);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Network address is invalid, ignoring assignment: %s", word);
                        return 0;
                }

                ipmask = new0(WireguardIpmask, 1);
                if (!ipmask)
                        return log_oom();
                ipmask->fields.family = family;
                ipmask->fields.ip6 = addr.in6;
                ipmask->fields.cidr = prefixlen;

                LIST_PREPEND(ipmasks, peer->ipmasks, ipmask);
                w->allocation_size += sizeof(struct wgipmask);
                peer->fields.num_ipmasks++;
        }

        return 0;
}

int config_parse_wireguard_endpoint(const char *unit,
                                    const char *filename,
                                    unsigned line,
                                    const char *section,
                                    unsigned section_line,
                                    const char *lvalue,
                                    int ltype,
                                    const char *rvalue,
                                    void *data,
                                    void *userdata) {
        Wireguard *w;
        WireguardPeer *peer;
        size_t len;
        const char *begin, *end = NULL;
        _cleanup_free_ char *host = NULL, *port = NULL;
        _cleanup_free_ WireguardEndpoint *endpoint = NULL;

        assert(data);
        assert(rvalue);

        w = WIREGUARD(data);

        assert(w);

        peer = wireguard_peer_new(w, section_line);
        if (!peer)
                return log_oom();

        endpoint = new0(WireguardEndpoint, 1);
        if (!endpoint)
                return log_oom();

        if (rvalue[0] == '[') {
                begin = &rvalue[1];
                end = strchr(rvalue, ']');
                if (!end) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Unable to find matching brace of endpoint, ignoring assignment: %s", rvalue);
                        return 0;
                }
                len = end - begin;
                ++end;
                if (*end != ':' || !*(end + 1)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Unable to find port of endpoint: %s", rvalue);
                        return 0;
                }
                ++end;
        } else {
                begin = rvalue;
                end = strrchr(rvalue, ':');
                if (!end || !*(end + 1)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Unable to find port of endpoint: %s", rvalue);
                        return 0;
                }
                len = end - begin;
                ++end;
        }

        host = strndup(begin, len);
        if (!host)
                return log_oom();

        port = strdup(end);
        if (!port)
                return log_oom();

        endpoint->peer = peer;
        endpoint->host = host;
        endpoint->port = port;
        LIST_PREPEND(endpoints, w->unresolved_endpoints, endpoint);
        w->n_unresolved_endpoints++;

        peer = NULL;
        host = NULL;
        port = NULL;
        endpoint = NULL;

        return 0;
}

int config_parse_wireguard_keepalive(const char *unit,
                                     const char *filename,
                                     unsigned line,
                                     const char *section,
                                     unsigned section_line,
                                     const char *lvalue,
                                     int ltype,
                                     const char *rvalue,
                                     void *data,
                                     void *userdata) {
        int r;
        uint16_t keepalive = 0;
        Wireguard *w;
        WireguardPeer *peer;

        assert(rvalue);
        assert(data);

        w = WIREGUARD(data);

        assert(w);

        peer = wireguard_peer_new(w, section_line);
        if (!peer)
                return log_oom();

        if (streq(rvalue, "off"))
                keepalive = 0;
        else {
                r = safe_atou16(rvalue, &keepalive);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r, "The persistent keepalive interval must be 0-65535. Ignore assignment: %s", rvalue);
        }

        peer->fields.persistent_keepalive_interval = keepalive;
        return 0;
}

static void wireguard_init(NetDev *netdev) {
        Wireguard *w;

        assert(netdev);

        w = WIREGUARD(netdev);

        assert(w);

        w->allocation_size = sizeof(struct wgdevice);
        w->dev.version_magic = WG_API_VERSION_MAGIC;
        w->dev.flags = WGDEVICE_REPLACE_PEERS | WGDEVICE_REMOVE_FWMARK | WGDEVICE_REMOVE_PRIVATE_KEY;
}

static void wireguard_done(NetDev *netdev) {
        Wireguard *w;
        WireguardEndpoint *endpoint, *endpoint_next;
        WireguardPeer *peer, *peer_next;
        WireguardIpmask *mask, *mask_next;

        assert(netdev);

        w = WIREGUARD(netdev);
        w->resolve_query = sd_resolve_query_unref(w->resolve_query);
        w->resolve_retry_event_source = sd_event_source_unref(w->resolve_retry_event_source);

        LIST_FOREACH_SAFE(endpoints, endpoint, endpoint_next, w->unresolved_endpoints) {
                w->n_unresolved_endpoints--;
                endpoint_free(endpoint);
        }

        LIST_FOREACH_SAFE(peers, peer, peer_next, w->peers) {
                LIST_FOREACH_SAFE(ipmasks, mask, mask_next, peer->ipmasks) {
                        free(mask);
                }
                free(peer);
        }
}

const NetDevVTable wireguard_vtable = {
        .object_size = sizeof(Wireguard),
        .sections = "Match\0NetDev\0Wireguard\0WireguardPeer\0",
        .post_create = netdev_wireguard_post_create,
        .init = wireguard_init,
        .done = wireguard_done,
        .create_type = NETDEV_CREATE_INDEPENDENT,
};

#pragma once

/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Userspace API for WireGuard
 * ---------------------------
 *
 * ioctl(WG_GET_DEVICE, { .ifr_name: "wg-1", .ifr_data: NULL }):
 *
 *     Returns the number of bytes required to hold the peers of a device (`ret_peers_size`).
 *
 * ioctl(WG_GET_DEVICE, { .ifr_name: "wg0", .ifr_data: user_pointer }):
 *
 *     Retrevies device info, peer info, and ipmask info.
 *
 *     `user_pointer` must point to a region of memory of size `sizeof(struct wgdevice) + ret_peers_size`
 *     and containing the structure `struct wgdevice { .peers_size: ret_peers_size }`.
 *
 *     Writes to `user_pointer` a succession of structs:
 *
 *         struct wgdevice { .num_peers = 3 }
 *             struct wgpeer { .num_ipmasks = 4 }
 *                 struct wgipmask
 *                 struct wgipmask
 *                 struct wgipmask
 *                 struct wgipmask
 *             struct wgpeer { .num_ipmasks = 2 }
 *                 struct wgipmask
 *                 struct wgipmask
 *             struct wgpeer { .num_ipmasks = 0 }
 *
 *     Returns 0 on success. Returns -EMSGSIZE if there is too much data for the size of passed-in
 *     memory, in which case, this should be recalculated using the call above. Returns -errno if another error occured.
 *
 * ioctl(WG_SET_DEVICE, { .ifr_name: "wg0", .ifr_data: user_pointer }):
 *
 *     Sets device info, peer info, and ipmask info.
 *
 *     `user_pointer` must point to a region of memory containing a succession of structs:
 *
 *         struct wgdevice { .num_peers = 3 }
 *             struct wgpeer { .num_ipmasks = 4 }
 *                 struct wgipmask
 *                 struct wgipmask
 *                 struct wgipmask
 *                 struct wgipmask
 *             struct wgpeer { .num_ipmasks = 2 }
 *                 struct wgipmask
 *                 struct wgipmask
 *             struct wgpeer { .num_ipmasks = 0 }
 *
 *     If `wgdevice->replace_peer_list` is true, removes all peers of device before adding new ones.
 *     If `wgpeer->remove_me` is true, the peer identified by `wgpeer->public_key` is removed.
 *     If `wgpeer->replace_ipmasks` is true, removes all ipmasks before adding new ones.
 *     If `wgdevice->private_key` is filled with zeros, no action is taken on the private key.
 *     If `wgdevice->preshared_key` is filled with zeros, no action is taken on the pre-shared key.
 *     If `wgdevice->remove_private_key` is true, the private key is removed.
 *     If `wgdevice->remove_preshared_key` is true, the pre-shared key is removed.
 *
 *     Returns 0 on success, or -errno if an error occurred.
 */


#include <stdint.h>
#include <sys/time.h>
#include <sys/socket.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#define WG_KEY_LEN 32

struct wgipmask {
        uint32_t family;
        union {
                struct in_addr ip4;
                struct in6_addr ip6;
        };
        uint8_t cidr;
};

struct wgpeer {
        uint8_t public_key[WG_KEY_LEN]; /* Get/Set */

        struct sockaddr_storage endpoint; /* Get/Set */

        struct timeval last_handshake_time; /* Get */
        uint64_t rx_bytes, tx_bytes; /* Get */

        uint32_t remove_me : 1; /* Set */
        uint32_t replace_ipmasks : 1; /* Set */

        uint16_t num_ipmasks; /* Get/Set */
        uint16_t persistent_keepalive_interval; /* Get/Set -- -1 = off, 0xffff = unset */
};

struct wgdevice {
        char interface[IFNAMSIZ]; /* Get */

        uint8_t public_key[WG_KEY_LEN]; /* Get/Set */
        uint8_t private_key[WG_KEY_LEN]; /* Get/Set */
        uint8_t preshared_key[WG_KEY_LEN]; /* Get/Set */

        uint16_t port; /* Get/Set */

        uint32_t replace_peer_list : 1; /* Set */
        uint32_t remove_private_key : 1; /* Set */
        uint32_t remove_preshared_key : 1; /* Set */

        union {
                uint16_t num_peers; /* Get/Set */
                uint64_t peers_size; /* Get */
        };
};

/* These are simply for convenience in iterating. It allows you to write something like:
 *
 *    for_each_wgpeer(device, peer, i) {
 *        for_each_wgipmask(peer, ipmask, j) {
 *            do_something_with_ipmask(ipmask);
 *        }
 *     }
 */

/*
#define for_each_wgpeer(__dev, __peer, __i) for ((__i) = 0, (__peer) = (struct wgpeer *)((uint8_t *)(__dev) + sizeof(struct wgdevice)); \
          (__i) < (__dev)->num_peers; \
           ++(__i), (__peer) = (struct wgpeer *)((uint8_t *)(__peer) + sizeof(struct wgpeer) + (sizeof(struct wgipmask) * (__peer)->num_ipmasks)))

#define for_each_wgipmask(__peer, __ipmask, __i) for ((__i) = 0, (__ipmask) = (struct wgipmask *)((uint8_t *)(__peer) + sizeof(struct wgpeer)); \
          (__i) < (__peer)->num_ipmasks; \
           ++(__i), (__ipmask) = (struct wgipmask *)((uint8_t *)(__ipmask) + sizeof(struct wgipmask)))
*/

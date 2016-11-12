/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include "conf-parser.h"
#include "networkd-util.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

const char *address_family_boolean_to_string(AddressFamilyBoolean b) {
        if (b == ADDRESS_FAMILY_YES ||
            b == ADDRESS_FAMILY_NO)
                return yes_no(b == ADDRESS_FAMILY_YES);

        if (b == ADDRESS_FAMILY_IPV4)
                return "ipv4";
        if (b == ADDRESS_FAMILY_IPV6)
                return "ipv6";

        return NULL;
}

AddressFamilyBoolean address_family_boolean_from_string(const char *s) {
        int r;

        /* Make this a true superset of a boolean */

        r = parse_boolean(s);
        if (r > 0)
                return ADDRESS_FAMILY_YES;
        if (r == 0)
                return ADDRESS_FAMILY_NO;

        if (streq(s, "ipv4"))
                return ADDRESS_FAMILY_IPV4;
        if (streq(s, "ipv6"))
                return ADDRESS_FAMILY_IPV6;

        return _ADDRESS_FAMILY_BOOLEAN_INVALID;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_address_family_boolean, address_family_boolean, AddressFamilyBoolean, "Failed to parse option");

int config_parse_address_family_boolean_with_kernel(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        AddressFamilyBoolean *fwd = data, s;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* This function is mostly obsolete now. It simply redirects
         * "kernel" to "no". In older networkd versions we used to
         * distuingish IPForward=off from IPForward=kernel, where the
         * former would explicitly turn off forwarding while the
         * latter would simply not touch the setting. But that logic
         * is gone, hence silently accept the old setting, but turn it
         * to "no". */

        s = address_family_boolean_from_string(rvalue);
        if (s < 0) {
                if (streq(rvalue, "kernel"))
                        s = ADDRESS_FAMILY_NO;
                else {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse IPForward= option, ignoring: %s", rvalue);
                        return 0;
                }
        }

        *fwd = s;

        return 0;
}

int ip_port_from_string(const char *s, uint16_t *port) {
        int r;
        uint16_t p;

        assert(s);
        assert(port);

        r = safe_atou16(s, &p);
        if (r < 0 || p == 0)
                return r;
        *port = p;
        return 0;
}

int parse_address_and_prefixlen(const char *s, int *family, union in_addr_union *addr, unsigned char *prefixlen) {
        const char *address, *end;
        int r;
        unsigned char p;

        assert(s);
        assert(prefixlen);

        end = strchr(s, '/');
        if (end)
                address = strndupa(s, end - s);
        else
                address = s;

        r = in_addr_from_string_auto(address, family, addr);
        if (r < 0)
                return r;

        if (end) {
                r = safe_atou8(end + 1, &p);
                if (r < 0 ||
                    (*family == AF_INET && p > 32) ||
                    (*family == AF_INET6 && p > 128))
                        return r;
                *prefixlen = p;

        } else
                *prefixlen = *family == AF_INET ? 32 : 128;
        return 0;
}

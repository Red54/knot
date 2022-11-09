/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "contrib/sockaddr.h"

struct knot_quic_reply;

struct knot_quic_reply *knot_qreq_connect(int fd, struct sockaddr_storage *rem_addr,
                                          const char *quic_cert, int timeout_ms);

int knot_qreq_send(struct knot_quic_reply *r, const struct iovec *data);

int knot_qreq_recv(struct knot_quic_reply *r, struct iovec *out, int timeout_ms);

void knot_qreq_close(struct knot_quic_reply *r);

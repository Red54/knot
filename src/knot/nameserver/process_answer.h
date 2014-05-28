/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "knot/nameserver/process_query.h"
#include "knot/nameserver/tsig_ctx.h"

/* Query processing module implementation. */
const knot_process_module_t *process_answer_get_module(void);
#define NS_PROC_ANSWER process_answer_get_module()
#define NS_PROC_ANSWER_ID 2

/*! \brief Answer processsing logging base. */
#define ANSWER_LOG(severity, data, what, msg...) do {\
	const char *zone_str = (data)->param->zone->conf->name; \
	NS_PROC_LOG(severity, LOG_SERVER, (data)->param->remote, zone_str, \
	            what " of '%s' from '%s': ", msg); \
	} while(0)

/* Module load parameters. */
struct process_answer_param {
	zone_t   *zone;
	const knot_pkt_t *query;
	const struct sockaddr_storage *remote;
	tsig_ctx_t tsig_ctx;
};

struct answer_data {
	/* Extensions. */
	void *ext;
	void (*ext_cleanup)(struct answer_data*); /*!< Extensions cleanup callback. */
	knot_sign_context_t sign;            /*!< Signing context. */

	/* Everything below should be kept on reset. */
	struct process_answer_param *param; /*!< Module parameters. */
	mm_ctx_t *mm;                      /*!< Memory context. */
};

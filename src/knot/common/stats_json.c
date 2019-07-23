/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/stats_json.h"

static void dump_counters_json(FILE *fd, mod_ctr_t *ctr, jsonw_t *w)
{
	jsonw2_list(w, NULL);
	for (uint32_t j = 0; j < ctr->count; j++) {
		uint64_t counter = ATOMIC_GET(ctr->counters[j]);
		// Skip empty counters.
		if (counter == 0) {
			continue;
		}

		if (ctr->idx_to_str != NULL) {
			char *str = ctr->idx_to_str(j, ctr->count);
			if (str != NULL) {
				jsonw2_ulong(w, str, counter);
				free(str);
			}
		} else {
			char buf[21];
			snprintf(buf, 21, "%u", j);
			jsonw2_ulong(w, buf, counter);
		}
	}
	jsonw2_end(w);
}

static void dump_modules_json(dump_ctx_t *ctx, jsonw_t *w)
{
	knotd_mod_t *mod = NULL;
	WALK_LIST(mod, *ctx->query_modules) {
		// Skip modules without statistics.
		if (mod->stats_count == 0) {
			continue;
		}

		// Dump zone name.
		if (ctx->zone != NULL) {
			// Prevent from zone section override.
			if (!ctx->zone_emitted) {
				jsonw2_list(w, "zones"); // Level 2 - Start
				ctx->zone_emitted = true;
			}

			char name[KNOT_DNAME_TXT_MAXLEN + 1];
			if (knot_dname_to_str(name, ctx->zone, sizeof(name)) == NULL) {
				return;
			}

			jsonw2_object(w, NULL); // Level 3 - Start
			jsonw2_str(w, "name", name);

			jsonw2_list(w, "modules"); // Level 4 - Start
		}

		// Dump module counters.
		jsonw2_object(w, NULL); // Level 5 - Start
		jsonw2_str(w, "name", mod->id->name + 1);
		jsonw2_object(w, "statistics"); // Level 6 - Start
		for (int i = 0; i < mod->stats_count; i++) {
			mod_ctr_t *ctr = mod->stats + i;
			if (ctr->name == NULL) {
				// Empty counter.
				continue;
			}
			if (ctr->count == 1) {
				// Simple counter.
				uint64_t counter = ATOMIC_GET(ctr->counter);
				jsonw2_ulong(w, ctr->name, counter);
			} else {
				// Array of counters.
				dump_counters_json(ctx->fd, ctr, w);
			}
		}
		jsonw2_end(w); // Level 6 - End
		jsonw2_end(w); // Level 5 - End
		jsonw2_end(w); // Level 4 - End
		jsonw2_end(w); // Level 3 - End
		jsonw2_end(w); // Level 2 - End
	}
}

static void zone_stats_dump_json(zone_t *zone, dump_ctx_t *ctx, jsonw_t *w)
{
	if (EMPTY_LIST(zone->query_modules)) {
		return;
	}

	ctx->query_modules = &zone->query_modules;
	ctx->zone = zone->name;

	dump_modules_json(ctx, w);
}


void dump_to_json(FILE *fd, server_t *server)
{
    char date[64] = "";

	jsonw_t *w = jsonw2_new(fd, "  ");
	if(!w) {
		return;
	}

	bool append = false;
	long pos = ftell(fd);
	while(pos > 0) {
		if(fgetc(fd) == ']') {
            // Rewrite end of JSON array with ',' for continue
			fseek(fd, --pos, SEEK_SET);
			fprintf(fd, ",\n");

			append = true;
            break;
		}
		fseek(fd, --pos, SEEK_SET);
	}

	if(!append) {
		fprintf(fd, "[");
	}

	// Get formatted current time string.
	struct tm tm;
	time_t now = time(NULL);
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S%z", &tm);

	// Get the server identity.
	conf_val_t val = conf_get(conf(), C_SRV, C_IDENT);
	const char *ident = conf_str(&val);
	if (ident == NULL || ident[0] == '\0') {
		ident = conf()->hostname;
	}

	jsonw2_object(w, NULL); // Level 1 - Start

	// Dump record header.
	jsonw2_str(w, "time", date);
	jsonw2_str(w, "identity", ident);

	// Dump server statistics.
	jsonw2_object(w, "server"); // Level 2 - Start
    for (const stats_item_t *item = server_stats; item->name != NULL; item++) {
		jsonw2_ulong(w, item->name, item->val(server));
	}
	jsonw2_end(w); // Level 2 - End

	dump_ctx_t ctx = {
		.fd = fd,
		.query_modules = conf()->query_modules,
	};

	//Dump global statistics.
	dump_modules_json(&ctx, w);

	// Dump zone statistics.
	knot_zonedb_foreach(server->zone_db, zone_stats_dump_json, &ctx, w);

	jsonw2_end(w); // Level 1 - End

	fprintf(fd, "\n]\n");
	jsonw2_free(w);
}

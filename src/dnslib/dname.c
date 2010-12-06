#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>	// tolower()

#include "dname.h"
#include "common.h"
#include "consts.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Returns the size of the wire format of domain name which has
 *        \a str_size characters in presentation format.
 */
static inline uint dnslib_dname_wire_size(uint str_size)
{
	return str_size + 1;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Converts domain name from string representation to wire format.
 *
 * This function also allocates the space for the wire format.
 *
 * \param name Domain name in string representation (presentation format).
 * \param size Size of the given domain name in characters (not counting the
 *             terminating 0 character.
 * \param wire [in/out] Pointer to position where the wire format of the domain
 *             name will be stored.
 *
 * \return Size of the wire format of the domain name in octets. If 0, no
 *         space has been allocated.
 *
 * \todo handle \X and \DDD (RFC 1035 5.1) or it can be handled by the parser?
 */
static uint dnslib_dname_str_to_wire(const char *name, uint size,
                                     uint8_t **wire)
{
	if (size > DNSLIB_MAX_DNAME_LENGTH) {
		return 0;
	}

	uint wire_size = dnslib_dname_wire_size(size);

	// signed / unsigned issues??
	*wire = (uint8_t *)malloc(wire_size * sizeof(uint8_t));
	if (*wire == NULL) {
		return 0;
	}

	debug_dnslib_dname("Allocated space for wire format of dname: %p\n",
	                   *wire);

	const uint8_t *ch = (const uint8_t *)name;
	uint8_t *label_start = *wire;
	uint8_t *w = *wire + 1;
	uint8_t label_length = 0;

	while (ch - (const uint8_t *)name < size) {
		assert(w - *wire < wire_size);
		assert(w - *wire - 1 == ch - (const uint8_t *)name);

		if (*ch == '.') {
			debug_dnslib_dname("Position %u (%p): "
					   "label length: %u\n",
			                   label_start - *wire,
					   label_start, label_length);
			*label_start = label_length;
			label_start = w;
			label_length = 0;
		} else {
			debug_dnslib_dname("Position %u (%p): character: %c\n",
			                   w - *wire, w, *ch);
			*w = *ch;
			++label_length;
		}

		++w;
		++ch;
		assert(ch >= (const uint8_t *)name);
	}

	// put 0 for root label if the name ended with .
	--ch;
	if (*ch == '.') {
		--w;
		debug_dnslib_dname("Position %u (%p): character: (null)\n",
				   w - *wire, w);
		*w = 0;
	} else {
		debug_dnslib_dname("Position %u (%p): "
				   "label length: %u\n",
			            label_start - *wire,
				    label_start, label_length);

		*label_start = label_length;
	}

	//memcpy(*wire, name, size);
	return wire_size;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new()
{
	dnslib_dname_t *dname = 
	(dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = NULL;
	dname->size = 0;
	dname->node = NULL;

	return dname;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new_from_str(char *name, uint size,
                                          struct dnslib_node *node)
{
	if (name == NULL || size == 0) {
		return NULL;
	}

	dnslib_dname_t *dname =
	(dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));

	if (name == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->size = dnslib_dname_str_to_wire(name, size, &dname->name);

	debug_dnslib_dname("Creating dname with size: %d\n", dname->size);

	if (dname->size <= 0) {
		log_warning("Could not parse domain name from string: '%.*s'\n",
		            size, name);
	}
	assert(dname->name != NULL);

	dname->node = node;

	return dname;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new_from_wire(uint8_t *name, uint size,
                                           struct dnslib_node *node)
{
	if (name == NULL && size != 0) {
		debug_dnslib_dname("No name given!\n");
		return NULL;
	}

	dnslib_dname_t *dname =
	(dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = (uint8_t *)malloc(size * sizeof(uint8_t));
	if (dname->name == NULL) {
		ERR_ALLOC_FAILED;
		free(dname);
		return NULL;
	}

	memcpy(dname->name, name, size);
	dname->size = size;
	dname->node = node;

	return dname;
}

/*----------------------------------------------------------------------------*/

char *dnslib_dname_to_str(const dnslib_dname_t *dname)
{
	char *name = (char *)malloc(dname->size * sizeof(char));

	uint8_t *w = dname->name;
	char *ch = name;
	int i = 0;

	if (dnslib_dname_is_fqdn(dname)) {
		while (i < dname->size && *w != 0) {
			int label_size = *(w++);
			// copy the label
			memcpy(ch, w, label_size);
			i += label_size;
			ch += label_size;
			w += label_size;
			*(ch++) = '.';
		}
		*ch = 0;
		assert(ch - name == dname->size - 1);
	} else {
		while (i < dname->size && (w - dname->name < dname->size)) {
			int label_size = *(w++);
			debug_dnslib_dname("Jumping ahead: %d chars.\n",
			                   label_size);
			// copy the label
			memcpy(ch, w, label_size);
			i += label_size;
			ch += label_size;
			w += label_size;
			*(ch++) = '.';
		}
		ch--;
		*ch = 0;
		assert(ch - name == dname->size - 1);
	}

	return name;
}

/*----------------------------------------------------------------------------*/

const uint8_t *dnslib_dname_name(const dnslib_dname_t *dname)
{
	return dname->name;
}

/*----------------------------------------------------------------------------*/

uint dnslib_dname_size(const dnslib_dname_t *dname)
{
	return dname->size;
}

/*----------------------------------------------------------------------------*/

const struct dnslib_node *dnslib_dname_node(const dnslib_dname_t *dname) {
	return dname->node;
}

/*----------------------------------------------------------------------------*/

int dnslib_dname_is_fqdn(const dnslib_dname_t *dname)
{
	return (dname->name[dname->size - 1] == '\0');
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_left_chop(const dnslib_dname_t *dname)
{
	dnslib_dname_t *parent = dnslib_dname_new();
	if (parent == NULL) {
		return NULL;
	}

	parent->size = dname->size - dname->name[0] - 1;
	parent->name = (uint8_t *)malloc(parent->size);
	if (parent->name == NULL) {
		ERR_ALLOC_FAILED;
		dnslib_dname_free(&parent);
		return NULL;
	}

	memcpy(parent->name, &dname->name[dname->name[0] + 1], parent->size);

	return parent;
}

/*----------------------------------------------------------------------------*/

void dnslib_dname_free(dnslib_dname_t **dname)
{
	if (dname == NULL || *dname == NULL) {
		return;
	}

	if ((*dname)->name != NULL) {
		free((*dname)->name);
	}
	free(*dname);
	*dname = NULL;
}

/*----------------------------------------------------------------------------*/

int dnslib_dname_compare(const dnslib_dname_t *d1, const dnslib_dname_t *d2)
{
	if (d1 == d2) {
		return 0;
	}

	// jump to the last label and store addresses of labels
	// on the way there
	// TODO: consider storing label offsets in the domain name structure
	const uint8_t *labels1[DNSLIB_MAX_DNAME_LABELS];
	const uint8_t *labels2[DNSLIB_MAX_DNAME_LABELS];
	int i1 = 0;
	int i2 = 0;

	const uint8_t *pos1 = dnslib_dname_name(d1);
	const uint8_t *pos2 = dnslib_dname_name(d2);

	while (*pos1 != '\0') {
		labels1[i1++] = pos1;
		pos1 += *pos1 + 1;
	}

	while (*pos2 != '\0') {
		labels2[i2++] = pos2;
		pos2 += *pos2 + 1;
	}

	// compare labels from last to first
	while (i1 > 0 && i2 > 0) {
		pos1 = labels1[--i1];
		pos2 = labels2[--i2];

		int label_length = (*pos1 < *pos2) ? *pos1 : *pos2;
		int i = 0;

		while (i < label_length && 
		       tolower(*(++pos1)) == tolower(*(++pos2))) {
			++i;
		}

		if (i < label_length) {	// difference in some octet
			if (tolower(*pos1) < tolower(*pos2)) {
				return -1;
			} else {
				assert(tolower(*pos1) > tolower(*pos2));
				return 1;
			}
		}

		if (*(labels1[i1]) < *(labels2[i2])) {	// one label shorter
			return -1;
		} else if (*(labels1[i1]) > *(labels2[i2])) {
			return 1;
		}
		// otherwise the labels are 
		// identical, continue with previous labels
	}

	// if all labels matched, the shorter name is first
	if (i1 == 0 && i2 > 0) {
		return 1;
	}

	if (i1 > 0 && i2 == 0) {
		return -1;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_cat(dnslib_dname_t *d1, const dnslib_dname_t *d2)
{
	if (d2->size == 0) {
		return d1;
	}

	if (dnslib_dname_is_fqdn(d1)) {
		return NULL;
	}

	// allocate new space
	uint8_t *new_dname = (uint8_t *)malloc(d1->size + d2->size);
	if (new_dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	memcpy(new_dname, d1->name, d1->size);
	memcpy(new_dname + d1->size, d2->name, d2->size);

	uint8_t *old_name = d1->name;
	d1->name = new_dname;
	d1->size += d2->size;
	free(old_name);

	return d1;
}

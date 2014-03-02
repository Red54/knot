#pragma once

#include "../binary.h"
#include "../key.h"

int dnssec_key_from_rsa_params(dnssec_key_t *key,
			       dnssec_key_algorithm_t algorithm,
			       const dnssec_binary_t *modulus,
			       const dnssec_binary_t *public_exponent,
			       const dnssec_binary_t *private_exponent,
			       const dnssec_binary_t *first_prime,
			       const dnssec_binary_t *second_prime,
			       const dnssec_binary_t *coefficient);

int dnssec_key_from_dsa_params(dnssec_key_t *key,
			       dnssec_key_algorithm_t algorithm,
			       const dnssec_binary_t *p,
			       const dnssec_binary_t *q,
			       const dnssec_binary_t *g,
			       const dnssec_binary_t *y,
			       const dnssec_binary_t *x);

int dnssec_key_from_ecdsa_params(dnssec_key_t *key,
                                 dnssec_key_algorithm_t algorithm,
			         const dnssec_binary_t *x_coordinate,
			         const dnssec_binary_t *y_coordinate,
			         const dnssec_binary_t *private_key);

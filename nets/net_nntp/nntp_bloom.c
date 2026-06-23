/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Bloom filter
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <math.h> /* use log() */
#include <stdint.h> /* use SIZE_MAX */

#include "nntp_bloom.h"

/* Minimal Bloom filter implementation for history */

/* Max Bloom filter size:
 * This is a strict limit for 32-bit systems to stay within size_t,
 * but we use the same limit for 64-bit systems right now as well
 * to avoid allocating a huge amount of memory.
 * Note that on either 32 or 64-bit systems, this may be larger
 * than the actual amount of memory available. */
#define BLOOM_MAX_BITS ((SIZE_MAX / 16) * 8)

#define BLOOM_MIN_BITS 64

/*
 * MurmurHash2, by Austin Appleby
 * Public domain code adapted from: https://github.com/aappleby/smhasher/blob/master/src/MurmurHash2.cpp
 */
static uint32_t murmurhash2(const void *key, int len, const uint32_t seed)
{
	const uint32_t m = 0x5bd1e995;
	const int r = 24; /* 'm' and 'r' are mixing constants generated offline. They're not really 'magic', they just happen to work well. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
	uint32_t h = (uint32_t) (seed ^ len); /* Initialize the hash to a 'random' value */
#pragma GCC diagnostic pop
	const unsigned char *data = (const unsigned char*) key;

	/* Mix 4 bytes at a time into the hash */
	while (len >= 4) {
		uint32_t k = *(const uint32_t*) data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
	/* Handle the last few bytes of the input array */
	switch (len) {
		case 3: h ^= (uint32_t) (data[2] << 16);
		case 2: h ^= (uint32_t) (data[1] << 8);
		case 1: h ^= (uint32_t) data[0];
		h *= m;
	}
#pragma GCC diagnostic pop

	/* Do a few final mixes of the hash to ensure the last few bytes are well-incorporated */
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}

void bloom_filter_add(struct bloom_filter *bf, const void *buf, int len)
{
	unsigned int i;
	uint32_t a = murmurhash2(buf, len, 0x9747b28c);
	uint32_t b = murmurhash2(buf, len, a);

	/* For each of the k hashes, set the bit to 1 */
	for (i = 0; i < bf->nhashes; i++) {
		size_t hashbit = (a + (b * i)) % bf->nbits;
		size_t hashbyte = hashbit / 8;
		bf->bits[hashbyte] |= (uint8_t) (1U << (hashbit % 8U));
	}
}

int bloom_filter_contains(const struct bloom_filter *bf, const void *buf, int len)
{
	unsigned int i;
	uint32_t a = murmurhash2(buf, len, 0x9747b28c);
	uint32_t b = murmurhash2(buf, len, a);

	/* For each of the k hashes, check if bit is 1; if any are not, definitely not in set; if all are, probably in the set */
	for (i = 0; i < bf->nhashes; i++) {
		size_t hashbit = (a + (b * i)) % bf->nbits;
		size_t hashbyte = hashbit / 8;
		if (!(bf->bits[hashbyte] & (uint8_t) (1U << (hashbit % 8U)))) {
			return 0;
		}
	}
	return 1;
}

unsigned int bloom_filter_bpe(size_t num_elements, unsigned long fp_inv)
{
	double error;

	/* Make the arguments sane if they weren't */
	if (!num_elements) {
		num_elements = 1;
	}
	if (fp_inv < 10) {
		fp_inv = 10;
	} else if (fp_inv > 10000000) {
		fp_inv = 10000000;
	}

	error = 1.0 / ((double) fp_inv);
	return (unsigned int) (-log(error) / 0.48045301391820); /* ln(2)^2 */
}

unsigned long bloom_filter_size(size_t num_elements, unsigned int bits_per_entry)
{
	unsigned long nbits;

	/* Calculate the number of bits we'll need for this number of elements
	 * (note the # could be an approximation, and that's fine). */
	if (num_elements > (SIZE_MAX / bits_per_entry)) {
		nbits = BLOOM_MAX_BITS;
	} else {
		nbits = (size_t) (bits_per_entry * num_elements);
	}
	if (nbits < BLOOM_MIN_BITS) {
		nbits = BLOOM_MIN_BITS;
	}
	return nbits;
}

static int _bloom_filter_init(struct bloom_filter *bf, size_t num_elements, unsigned long fp_inv)
{
	unsigned int bits_per_entry;
	size_t nbytes;

	memset(bf, 0, sizeof(struct bloom_filter));
	bits_per_entry = bloom_filter_bpe(num_elements, fp_inv);
	bf->nhashes = (unsigned int) ceil(0.693147180559945 * bits_per_entry); /* ln(2) */
	bf->nbits = bloom_filter_size(num_elements, bits_per_entry);
	nbytes = (bf->nbits + 7) / 8; /* round up to the nearest whole # of byte */

	/* Use the real calloc here so that we don't log an error on allocation failure in case we retry with a smaller # of bytes */
#undef calloc
	bf->bits = calloc(1, nbytes);
	if (!bf->bits) {
		errno = ENOMEM;
		return -1;
	}

	bbs_debug(7, "Created Bloom filter with %lu B (1/%lu f.p.)\n", nbytes, fp_inv);
	bf->count = 0;
	return 0;
}

int bloom_filter_init(struct bloom_filter *bf, size_t num_elements, unsigned long fp_inv)
{
	if (_bloom_filter_init(bf, num_elements, fp_inv)) {
		bbs_error("Failed to initialize Bloom filter (insufficient memory for %lu elements, %lu f.p.)\n", num_elements, fp_inv);
		return -1;
	}
	return 0;
}

int bloom_filter_autoinit(struct bloom_filter *bf, size_t num_elements)
{
	/* Automatically choose a sensible value for fp_inv based on the # of elements and available system memory */
	unsigned long fp_inv = num_elements; /* Start out with 1 false positive for the whole set, and reduce precision if needed */
	if (num_elements > 8388608) {
		fp_inv /= 10;
	} else if (num_elements > 1048576) {
		fp_inv /= 5;
	}
	/*! \todo If the amount of memory we would allocate is fairly close to the overall system limit (or above it),
	 * preemptively cut precision to avoid a failed allocation in the first place,
	 * or worse, a big enough allocation that future allocations elsewhere might fail due to low system memory.
	 * Regardless, less memory may be available so we still have to handle allocation failure. */
	for (;;) {
		if (!_bloom_filter_init(bf, num_elements, fp_inv)) {
			return 0;
		}
		/* If allocation failed because the resulting Bloom filter would be too large,
		 * reduce the precision and try again. */
		bbs_debug(7, "Retrying Bloom filter creation with 1/%lu f.p.\n", fp_inv);
		fp_inv /= 10;
		if (fp_inv <= 10) { /* No point in having worse than 10% false positive rate */
			return -1;
		}
	}
}

void bloom_filter_destroy(struct bloom_filter *bf)
{
	free_if(bf->bits);
}

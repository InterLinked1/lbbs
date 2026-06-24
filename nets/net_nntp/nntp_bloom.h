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
 */

struct bloom_filter {
	uint8_t *bits; /* bit array */
	size_t nbits; /* Total bits (m) */
	unsigned int nhashes; /* # of hash functions (k) */
	size_t count; /* # of entries added to the filter */
};

/*!
 * \brief Calculate the bits per entry for a Bloom filter
 * \param fp_inv Reciprocal of desired false positive rate
 * \returns The bits per entry
 */
unsigned int bloom_filter_bpe(unsigned long fp_inv);

/*!
 * \brief Calculate the space that would be required for a Bloom filter
 * \param num_elements Estimated number of elements that will be added to the Bloom filter. (Actual number can vary.)
 * \param bits_per_entry The result of bloom_filter_bpe()
 * \returns Number of bytes of resulting Bloom filter if bloom_filter_init() is called
 */
unsigned long bloom_filter_size(size_t num_elements, unsigned int bits_per_entry);

/*!
 * \brief Initialize Bloom filter
 * \param[out] bf
 * \param num_elements Estimated number of elements that will be added to the Bloom filter. (Actual number can vary.)
 * \param fp_inv Reciprocal of desired false positive rate
 * \retval 0 on success, -1 if allocation failed
 */
int bloom_filter_init(struct bloom_filter *bf, size_t num_elements, unsigned long fp_inv);

/*!
 * \brief Initialize Bloom filter and automatically use an appropriate value for the desired false positive rate
 * \param[out] bf
 * \param num_elements Estimated number of elements that will be added to the Bloom filter. (Actual number can vary.)
 * \retval 0 on success, -1 if allocation failed
 */
int bloom_filter_autoinit(struct bloom_filter *bf, size_t num_elements);

/*! \brief Free memory from an initialized Bloom filter */
void bloom_filter_destroy(struct bloom_filter *bf);

/*!
 * \brief Add an element to the Bloom filter
 * \param bf
 * \param buf Item to add
 * \param len Length of buf
 */
void bloom_filter_add(struct bloom_filter *bf, const void *buf, int len);

/*!
 * \brief Check whether an item is in the Bloom filter
 * \param bf
 * \param buf Item to check for
 * \param len Length of buf
 * \retval 1 Bloom filter contains item (i.e. it is probably in the set, but not guaranteed to be, so membership may need to be verified)
 * \retval 0 Bloom filter doesn't contain item (i.e. it is definitely NOT in the set)
 */
int bloom_filter_contains(const struct bloom_filter *bf, const void *buf, int len);

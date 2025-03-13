/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 */

/*! \file
 *
 * \brief Compression Functions for Test Suite
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

struct z_data *z_client_new(int fd);

#define REQUIRE_ZLIB_CLIENT(z) if (!z) { goto cleanup; }

void z_client_free(struct z_data *z);

#define ZLIB_CLIENT_SHUTDOWN(z) if (z) { z_client_free(z); z = NULL; }

ssize_t zlib_write(struct z_data *z, int line, const char *buf, size_t len);

ssize_t zlib_read(struct z_data *z, int line, char *buf, size_t len);

int test_z_client_expect(struct z_data *z, int ms, const char *s, int line);
int test_z_client_expect_buf(struct z_data *z, int ms, const char *s, int line, char *buf, size_t len);
int test_z_client_expect_eventually(struct z_data *z, int ms, const char *s, int line);
int test_z_client_expect_eventually_buf(struct z_data *z, int ms, const char *s, int line, char *buf, size_t len);

#define ZLIB_CLIENT_EXPECT(z, s) if (test_z_client_expect(z, SEC_MS(5), s, __LINE__)) { goto cleanup; }
#define ZLIB_CLIENT_EXPECT_BUF(z, s, buf) if (test_z_client_expect_buf(z, SEC_MS(5), s, __LINE__, buf, sizeof(buf))) { goto cleanup; }
#define ZLIB_CLIENT_EXPECT_EVENTUALLY(z, s) if (test_z_client_expect_eventually(z, SEC_MS(5), s, __LINE__)) { goto cleanup; }

#define ZLIB_SWRITE(z, s) if (zlib_write(z, __LINE__, s, STRLEN(s)) < 0) { goto cleanup; }

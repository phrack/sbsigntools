/*
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the OpenSSL
 * library under certain conditions as described in each individual source file,
 * and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <ccan/talloc/talloc.h>
#include <ccan/read_write_all/read_write_all.h>

#include "fileio.h"

#define FLAG_NOERROR	(1<<0)

static int ui_read(UI *ui, UI_STRING *uis)
{
	char password[128];

	if (UI_get_string_type(uis) != UIT_PROMPT)
		return 0;

	EVP_read_pw_string(password, sizeof(password), "Enter engine key pass phrase:", 0);
	UI_set_result(ui, uis, password);
	return 1;
}

ENGINE *setup_engine(const char* engine, UI_METHOD *ui) 
{
	ENGINE *e;
	ENGINE_load_dynamic();
	e = ENGINE_by_id(engine);

	if (!e) {
		fprintf(stderr, "Failed to load engine: %s\n", engine);
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	ui = UI_create_method("sbsigntools");
	if (!ui) {
		fprintf(stderr, "Failed to create UI method\n");
		ERR_print_errors_fp(stderr);
		ENGINE_free(e);
		return NULL;
	}
	UI_method_set_reader(ui, ui_read);

	ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ui,
	                0, 1);

	if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
	    fprintf(stderr, "can't use that engine\n");
	    ERR_print_errors_fp(stderr);
	    ENGINE_free(e);
	    return NULL;
	}

	return e;
}

EVP_PKEY *fileio_read_engine_key(ENGINE *e, const char *filename, const uint8_t keyform, UI_METHOD *ui)
{	
	EVP_PKEY *pkey = NULL;

	if (keyform == KEYFORM_PEM) {
		// Some HSMs use a safety key where a fake key is stored in a PEM file
		// and this key is mapped to the real key in the HSM
		pkey = fileio_read_pkey(filename);
	} else if (keyform == KEYFORM_ENGINE) {
		pkey = ENGINE_load_private_key(e, filename, ui, NULL);
	} else {
		fprintf(stderr, "Unrecognized keyform\n");
		ERR_print_errors_fp(stderr);
	}

	return pkey;
}

EVP_PKEY *fileio_read_pkey(const char *filename)
{
	EVP_PKEY *key = NULL;
	BIO *bio;

	bio = BIO_new_file(filename, "r");
	if (!bio)
		goto out;

	key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

out:
	BIO_free_all(bio);
	if (!key) {
		fprintf(stderr, "Can't load key from file '%s'\n", filename);
		ERR_print_errors_fp(stderr);
	}
	return key;
}

X509 *fileio_read_cert(const char *filename)
{
	X509 *cert = NULL;
	BIO *bio;

	bio = BIO_new_file(filename, "r");
	if (!bio)
		goto out;

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

out:
	BIO_free_all(bio);
	if (!cert) {
		fprintf(stderr, "Can't load certificate from file '%s'\n",
				filename);
		ERR_print_errors_fp(stderr);
	}
	return cert;
}

static int __fileio_read_file(void *ctx, const char *filename,
		 uint8_t **out_buf, size_t *out_len, int flags)
{
	struct stat statbuf;
	uint8_t *buf;
	size_t len;
	int fd, rc;

	rc = -1;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		goto out;

	rc = fstat(fd, &statbuf);
	if (rc)
		goto out;

	len = statbuf.st_size;

	buf = talloc_array(ctx, uint8_t, len);
	if (!buf)
		goto out;

	if (!read_all(fd, buf, len))
		goto out;

	rc = 0;

out:
	if (fd >= 0)
		close(fd);
	if (rc) {
		if (!(flags & FLAG_NOERROR))
			fprintf(stderr, "Error reading file %s: %s\n",
					filename, strerror(errno));
	} else {
		*out_buf = buf;
		*out_len = len;
	}
	return rc;

}

int fileio_read_file(void *ctx, const char *filename,
		 uint8_t **out_buf, size_t *out_len)
{
	return __fileio_read_file(ctx, filename, out_buf, out_len, 0);
}

int fileio_read_file_noerror(void *ctx, const char *filename,
		 uint8_t **out_buf, size_t *out_len)
{
	return __fileio_read_file(ctx, filename, out_buf, out_len,
			FLAG_NOERROR);
}

int fileio_write_file(const char *filename, uint8_t *buf, size_t len)
{
	int fd;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	if (!write_all(fd, buf, len)) {
		perror("write_all");
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

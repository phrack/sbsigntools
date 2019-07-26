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
#ifndef FILEIO_H
#define FILEIO_H

#include <stdint.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#define KEYFORM_PEM	1
#define KEYFORM_ENGINE	2

ENGINE *setup_engine(const char* engine, UI_METHOD *ui);
EVP_PKEY *fileio_read_pkey(const char *filename);
EVP_PKEY *fileio_read_engine_key(ENGINE *e, const char *filename, const uint8_t keyform, UI_METHOD *ui);
X509 *fileio_read_cert(const char *filename);

int fileio_read_file(void *ctx, const char *filename,
		uint8_t **out_buf, size_t *out_len);
int fileio_read_file_noerror(void *ctx, const char *filename,
		 uint8_t **out_buf, size_t *out_len);
int fileio_write_file(const char *filename, uint8_t *buf, size_t len);

#endif /* FILEIO_H */


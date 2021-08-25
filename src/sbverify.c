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
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <getopt.h>

#include <ccan/talloc/talloc.h>
#include <ccan/read_write_all/read_write_all.h>

#include "image.h"
#include "idc.h"
#include "fileio.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_OBJECT_get0_X509(obj) ((obj)->data.x509)
#define X509_OBJECT_get_type(obj) ((obj)->type)
#define X509_STORE_CTX_get0_cert(ctx) ((ctx)->cert)
#define X509_STORE_get0_objects(certs) ((certs)->objs)
#define X509_get_extended_key_usage(cert) ((cert)->ex_xkusage)
#if OPENSSL_VERSION_NUMBER < 0x10020000L
#define X509_STORE_CTX_get0_store(ctx) ((ctx)->ctx)
#endif
#endif

static const char *toolname = "sbverify";
static const int cert_name_len = 160;

enum verify_status {
	VERIFY_FAIL = 0,
	VERIFY_OK = 1,
};

static struct option options[] = {
	{ "cert", required_argument, NULL, 'c' },
	{ "list", no_argument, NULL, 'l' },
	{ "detached", required_argument, NULL, 'd' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s [options] --cert <certfile> <efi-boot-image>\n"
		"Verify a UEFI secure boot image.\n\n"
		"Options:\n"
		"\t--cert <certfile>  certificate (x509 certificate)\n"
		"\t--list             list all signatures (but don't verify)\n"
		"\t--detached <file>  read signature from <file>, instead of\n"
		"\t                    looking for an embedded signature\n",
			toolname);
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}

int load_cert(X509_STORE *certs, const char *filename)
{
	X509 *cert;

	cert = fileio_read_cert(filename);
	if (!cert)
		return -1;

	X509_STORE_add_cert(certs, cert);
	return 0;
}

static void print_signature_info(PKCS7 *p7)
{
	char subject_name[cert_name_len + 1], issuer_name[cert_name_len + 1];
	PKCS7_SIGNER_INFO *si;
	X509 *cert;
	int i;

	printf("image signature issuers:\n");

	for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(p7->d.sign->signer_info);
			i++) {
		si = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, i);
		X509_NAME_oneline(si->issuer_and_serial->issuer,
				issuer_name, cert_name_len);
		printf(" - %s\n", issuer_name);
	}

	printf("image signature certificates:\n");

	for (i = 0; i < sk_X509_num(p7->d.sign->cert); i++) {
		cert = sk_X509_value(p7->d.sign->cert, i);
		X509_NAME_oneline(X509_get_subject_name(cert),
				subject_name, cert_name_len);
		X509_NAME_oneline(X509_get_issuer_name(cert),
				issuer_name, cert_name_len);

		printf(" - subject: %s\n", subject_name);
		printf("   issuer:  %s\n", issuer_name);
	}
}

static void print_certificate_store_certs(X509_STORE *certs)
{
	char subject_name[cert_name_len + 1], issuer_name[cert_name_len + 1];
	STACK_OF(X509_OBJECT) *objs;
	X509_OBJECT *obj;
	X509 *cert;
	int i;

	printf("certificate store:\n");

	objs = X509_STORE_get0_objects(certs);

	for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
		obj = sk_X509_OBJECT_value(objs, i);

		if (X509_OBJECT_get_type(obj) != X509_LU_X509)
			continue;

		cert = X509_OBJECT_get0_X509(obj);

		X509_NAME_oneline(X509_get_subject_name(cert),
				subject_name, cert_name_len);
		X509_NAME_oneline(X509_get_issuer_name(cert),
				issuer_name, cert_name_len);

		printf(" - subject: %s\n", subject_name);
		printf("   issuer:  %s\n", issuer_name);
	}
}

static int load_detached_signature_data(struct image *image,
		const char *filename, uint8_t **buf, size_t *len)
{
	return fileio_read_file(image, filename, buf, len);
}

static int cert_in_store(X509 *cert, X509_STORE_CTX *ctx)
{
	STACK_OF(X509_OBJECT) *objs;
	X509_OBJECT *obj;
	int i;

	objs = X509_STORE_get0_objects(X509_STORE_CTX_get0_store(ctx));

	for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
		obj = sk_X509_OBJECT_value(objs, i);

		if (X509_OBJECT_get_type(obj) == X509_LU_X509 &&
		    !X509_cmp(X509_OBJECT_get0_X509(obj), cert))
			return 1;
	}

	return 0;
}

static int x509_verify_cb(int status, X509_STORE_CTX *ctx)
{
	int err = X509_STORE_CTX_get_error(ctx);

	/* also accept code-signing keys */
	if (err == X509_V_ERR_INVALID_PURPOSE &&
			X509_get_extended_key_usage(X509_STORE_CTX_get0_cert(ctx))
			== XKU_CODE_SIGN)
		status = 1;

	else if (err == X509_V_ERR_CERT_UNTRUSTED ||
		 err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ||
		 err == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) {
		/* all certs given with the --cert argument are trusted */

		if (cert_in_store(X509_STORE_CTX_get_current_cert(ctx), ctx))
			status = 1;
	} else if (err == X509_V_ERR_CERT_HAS_EXPIRED ||
		   err == X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD ||
		   err == X509_V_ERR_CERT_NOT_YET_VALID ||
		   err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
		   err == X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD)
		/* UEFI explicitly allows expired certificates */
		status = 1;

	return status;
}

int main(int argc, char **argv)
{
	const char *detached_sig_filename, *image_filename;
	enum verify_status status;
	int rc, c, flags, list;
	const uint8_t *tmp_buf;
	struct image *image;
	X509_STORE *certs;
	uint8_t *sig_buf;
	size_t sig_size;
	struct idc *idc;
	int verbose;
	BIO *idcbio;
	PKCS7 *p7;
	int sig_count = 0;

	status = VERIFY_FAIL;
	certs = X509_STORE_new();
	list = 0;
	verbose = 0;
	detached_sig_filename = NULL;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OPENSSL_config(NULL);
#else
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif
	/* here we may get highly unlikely failures or we'll get a
	 * complaint about FIPS signatures (usually becuase the FIPS
	 * module isn't present).  In either case ignore the errors
	 * (malloc will cause other failures out lower down */
	ERR_clear_error();

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "c:d:lvVh", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			rc = load_cert(certs, optarg);
			if (rc)
				return EXIT_FAILURE;
			break;
		case 'd':
			detached_sig_filename = optarg;
			break;
		case 'l':
			list = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			version();
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		}

	}

	if (argc != optind + 1) {
		usage();
		return EXIT_FAILURE;
	}

	image_filename = argv[optind];

	image = image_load(image_filename);
	if (!image) {
		fprintf(stderr, "Can't open image %s\n", image_filename);
		return EXIT_FAILURE;
	}

	for (;;) {
		if (detached_sig_filename) {
			if (sig_count++)
				break;

			rc = load_detached_signature_data(image, detached_sig_filename,
							  &sig_buf, &sig_size);
		} else
			rc = image_get_signature(image, sig_count++, &sig_buf, &sig_size);

		if (rc) {
			if (sig_count == 0) {
				fprintf(stderr, "Unable to read signature data from %s\n",
					detached_sig_filename ? : image_filename);
			}
			break;
		}

		tmp_buf = sig_buf;
		if (verbose || list)
			printf("signature %d\n", sig_count);
		p7 = d2i_PKCS7(NULL, &tmp_buf, sig_size);
		if (!p7) {
			fprintf(stderr, "Unable to parse signature data\n");
			ERR_print_errors_fp(stderr);
			break;
		}

		if (verbose || list) {
			print_signature_info(p7);
			if (verbose > 1)
				print_certificate_store_certs(certs);
		}

		if (list)
			continue;

		idcbio = BIO_new(BIO_s_mem());
		idc = IDC_get(p7, idcbio);
		if (!idc) {
			fprintf(stderr, "Unable to get IDC from PKCS7\n");
			break;
		}

		rc = IDC_check_hash(idc, image);
		if (rc) {
			fprintf(stderr, "Image fails hash check\n");
			break;
		}

		flags = PKCS7_BINARY;

		/* OpenSSL 1.0.2e no longer allows calling PKCS7_verify with
		 * both data and content. Empty out the content. */
		p7->d.sign->contents->d.ptr = NULL;

		X509_STORE_set_verify_cb_func(certs, x509_verify_cb);
		rc = PKCS7_verify(p7, NULL, certs, idcbio, NULL, flags);
		if (rc) {
			if (verbose)
				printf("PKCS7 verification passed\n");

			status = VERIFY_OK;
		} else if (verbose) {
			printf("PKCS7 verification failed\n");
			ERR_print_errors_fp(stderr);
		}

	}

	talloc_free(image);

	if (list)
		exit(EXIT_SUCCESS);

	if (status == VERIFY_OK)
		printf("Signature verification OK\n");
	else
		printf("Signature verification failed\n");

	return status == VERIFY_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}

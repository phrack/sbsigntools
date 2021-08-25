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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

#include <getopt.h>

#include <openssl/conf.h>
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <ccan/talloc/talloc.h>
#include <ccan/read_write_all/read_write_all.h>

#include "config.h"

#include "image.h"
#include "fileio.h"

static const char *toolname = "sbattach";

static struct option options[] = {
	{ "attach", required_argument, NULL, 'a' },
	{ "detach", required_argument, NULL, 'd' },
	{ "remove", no_argument, NULL, 'r' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ "signum", required_argument, NULL, 's' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s --attach <sigfile> <efi-boot-image>\n"
		"   or: %s --detach <sigfile> [--remove] <efi-boot-image>\n"
		"   or: %s --remove <efi-boot-image>\n"
		"Attach or detach a signature file to/from a boot image\n"
		"\n"
		"Options:\n"
		"\t--attach <sigfile>  set <sigfile> as the boot image's\n"
		"\t                     signature table\n"
		"\t--detach <sigfile>  copy the boot image's signature table\n"
		"\t                     to <sigfile>\n"
		"\t--remove            remove the boot image's signature\n"
		"\t                     table from the original file\n"
	        "\t--signum            signature to operate on (defaults to\n"
	        "\t                     first)\n",
		toolname, toolname, toolname);
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}

static int detach_sig(struct image *image, int signum, const char *sig_filename)
{
	return image_write_detached(image, signum, sig_filename);
}

static int attach_sig(struct image *image, const char *image_filename,
		const char *sig_filename)
{
	const uint8_t *tmp_buf;
	uint8_t *sigbuf;
	size_t size;
	PKCS7 *p7;
	int rc;

	rc = fileio_read_file(image, sig_filename, &sigbuf, &size);
	if (rc)
		goto out;

	image_add_signature(image, sigbuf, size);

	rc = -1;
	tmp_buf = sigbuf;
	p7 = d2i_PKCS7(NULL, &tmp_buf, size);
	if (!p7) {
		fprintf(stderr, "Unable to parse signature data in file: %s\n",
				sig_filename);
		ERR_print_errors_fp(stderr);
		goto out;
	}
	rc = PKCS7_verify(p7, NULL, NULL, NULL, NULL,
				PKCS7_BINARY | PKCS7_NOVERIFY | PKCS7_NOSIGS);
	if (!rc) {
		fprintf(stderr, "PKCS7 verification failed for file %s\n",
				sig_filename);
		ERR_print_errors_fp(stderr);
		goto out;
	}

	rc = image_write(image, image_filename);
	if (rc)
		fprintf(stderr, "Error writing %s: %s\n", image_filename,
				strerror(errno));

out:
	talloc_free(sigbuf);
	return rc;
}

static int remove_sig(struct image *image, int signum,
		      const char *image_filename)
{
	int rc;

	rc = image_remove_signature(image, signum);

	if (rc) {
		fprintf(stderr, "Error, image has no signature at %d\n",
			signum + 1);
		return rc;
	}

	rc = image_write(image, image_filename);
	if (rc)
		fprintf(stderr, "Error writing %s: %s\n", image_filename,
				strerror(errno));

	return rc;
}

enum action {
	ACTION_NONE,
	ACTION_ATTACH,
	ACTION_DETACH,
};

int main(int argc, char **argv)
{
	const char *image_filename, *sig_filename;
	struct image *image;
	enum action action;
	bool remove;
	int c, rc, signum = 0;

	action = ACTION_NONE;
	sig_filename = NULL;
	remove = false;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "a:d:s:rhV", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
		case 'd':
			if (action != ACTION_NONE) {
				fprintf(stderr, "Multiple actions specified\n");
				usage();
				return EXIT_FAILURE;
			}
			action = (c == 'a') ? ACTION_ATTACH : ACTION_DETACH;
			sig_filename = optarg;
			break;
		case 's':
			/* humans count from 1 not zero */
			signum = atoi(optarg) - 1;
			break;
		case 'r':
			remove = true;
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

	/* sanity check action combinations */
	if (action == ACTION_ATTACH && remove) {
		fprintf(stderr, "Can't use --remove with --attach\n");
		return EXIT_FAILURE;
	}

	if (action == ACTION_NONE && !remove) {
		fprintf(stderr, "No action (attach/detach/remove) specified\n");
		usage();
		return EXIT_FAILURE;
	}

	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
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

	image = image_load(image_filename);
	if (!image) {
		fprintf(stderr, "Can't load image file %s\n", image_filename);
		return EXIT_FAILURE;
	}

	rc = 0;

	if (action == ACTION_ATTACH)
		rc = attach_sig(image, image_filename, sig_filename);

	else if (action == ACTION_DETACH)
		rc = detach_sig(image, signum, sig_filename);

	if (rc)
		goto out;

	if (remove)
		rc = remove_sig(image, signum, image_filename);

out:
	talloc_free(image);
	return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

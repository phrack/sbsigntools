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
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <getopt.h>

#include <uuid/uuid.h>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>

#include <ccan/array_size/array_size.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/talloc/talloc.h>

#include "efivars.h"
#include "fileio.h"

static const char *toolname = "sbvarsign";

struct varsign_context {
	const char			*infilename;
	const char			*outfilename;

	uint8_t				*data;
	size_t				data_len;

	CHAR16				*var_name;
	int				var_name_bytes;
	EFI_GUID			var_guid;
	uint32_t			var_attrs;

	EVP_PKEY			*key;
	X509				*cert;

	EFI_VARIABLE_AUTHENTICATION_2	*auth_descriptor;
	int				auth_descriptor_len;
	EFI_TIME			timestamp;

	int				verbose;
};

struct attr {
	const char	*name;
	int		value;
};

#define EFI_VAR_ATTR(n) { #n, EFI_VARIABLE_ ## n }
static struct attr attrs[] = {
	EFI_VAR_ATTR(NON_VOLATILE),
	EFI_VAR_ATTR(BOOTSERVICE_ACCESS),
	EFI_VAR_ATTR(RUNTIME_ACCESS),
	EFI_VAR_ATTR(TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
	EFI_VAR_ATTR(APPEND_WRITE),
};

static uint32_t default_attrs = EFI_VARIABLE_NON_VOLATILE |
			EFI_VARIABLE_BOOTSERVICE_ACCESS |
			EFI_VARIABLE_RUNTIME_ACCESS |
			EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
			EFI_VARIABLE_APPEND_WRITE;

static uint32_t attr_invalid = 0xffffffffu;
static const char *attr_prefix = "EFI_VARIABLE_";

static const EFI_GUID cert_pkcs7_guid = EFI_CERT_TYPE_PKCS7_GUID;

static void set_default_outfilename(struct varsign_context *ctx)
{
	const char *extension = "signed";

	ctx->outfilename = talloc_asprintf(ctx, "%s.%s",
			ctx->infilename, extension);
}

static uint32_t parse_single_attr(const char *attr_str)
{
	unsigned int i;

	/* skip standard prefix, if present */
	if (!strncmp(attr_str, attr_prefix, strlen(attr_prefix)))
		attr_str += strlen(attr_prefix);

	for (i = 0; i < ARRAY_SIZE(attrs); i++) {
		if (!strcmp(attr_str, attrs[i].name))
			return attrs[i].value;
	}

	return attr_invalid;
}

static uint32_t parse_attrs(const char *attrs_str)
{
	uint32_t attr, attrs_val;
	const char *attr_str;
	char *str;

	/* we always need E_V_T_B_A_W_A */
	attrs_val = EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

	if (!attrs_str[0])
		return attrs_val;

	str = strdup(attrs_str);

	for (attr_str = strtok(str, ","); attr_str;
			attr_str = strtok(NULL, ",")) {

		attr = parse_single_attr(attr_str);
		if (attr == attr_invalid) {
			fprintf(stderr, "Invalid attribute string %s\n",
					attr_str);
			return attr_invalid;
		}

		attrs_val |= attr;
	}

	return attrs_val;
}

static int set_varname(struct varsign_context *ctx, const char *str)
{
	CHAR16 *wstr;
	int i, len;

	len = strlen(str);

	wstr = talloc_array(ctx, CHAR16, len);

	for (i = 0; i < len; i++)
		wstr[i] = str[i];

	ctx->var_name = wstr;
	ctx->var_name_bytes = len * sizeof(CHAR16);

	return 0;
}

static int parse_guid(const char *str, EFI_GUID *guid)
{
	uuid_t uuid;

	if (uuid_parse(str, uuid))
		return -1;

	/* convert to an EFI_GUID */
	guid->Data1 = uuid[0] << 24 | uuid[1] << 16 | uuid[2] << 8 | uuid[3];
	guid->Data2 = uuid[4] << 8 | uuid[5];
	guid->Data3 = uuid[6] << 8 | uuid[7];
	memcpy(guid->Data4, &uuid[8], sizeof(guid->Data4));

	return 0;
}

static int set_timestamp(EFI_TIME *timestamp)
{
	struct tm *tm;
	time_t t;

	time(&t);

	tm = gmtime(&t);
	if (!tm) {
		perror("gmtime");
		return -1;
	}

	/* copy to our EFI-specific time structure. Other fields (Nanosecond,
	 * TimeZone, Daylight and Pad) are defined to be zero */
	memset(timestamp, 0, sizeof(*timestamp));
	timestamp->Year = 1900 + tm->tm_year;
	timestamp->Month = tm->tm_mon;
	timestamp->Day = tm->tm_mday;
	timestamp->Hour = tm->tm_hour;
	timestamp->Minute = tm->tm_min;
	timestamp->Second = tm->tm_sec;

	return 0;
}

static int add_auth_descriptor(struct varsign_context *ctx)
{
	EFI_VARIABLE_AUTHENTICATION_2 *auth;
	int rc, len, flags;
	EFI_TIME timestamp;
	const EVP_MD *md;
	BIO *data_bio;
	uint8_t *tmp;
	PKCS7 *p7;

	if (set_timestamp(&timestamp))
		return -1;

	/* create a BIO for our variable data, containing:
	 *  * Variablename (not including trailing nul)
	 *  * VendorGUID
	 *  * Attributes
	 *  * TimeStamp
	 *  * Data
	 */
	data_bio = BIO_new(BIO_s_mem());
	BIO_write(data_bio, ctx->var_name, ctx->var_name_bytes);
	BIO_write(data_bio, &ctx->var_guid, sizeof(ctx->var_guid));
	BIO_write(data_bio, &ctx->var_attrs, sizeof(ctx->var_attrs));
	BIO_write(data_bio, &timestamp, sizeof(timestamp));
	BIO_write(data_bio, ctx->data, ctx->data_len);

	md = EVP_get_digestbyname("SHA256");

	p7 = PKCS7_new();
	flags = PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOSMIMECAP;;
	PKCS7_set_type(p7, NID_pkcs7_signed);

	PKCS7_content_new(p7, NID_pkcs7_data);

	PKCS7_sign_add_signer(p7, ctx->cert, ctx->key, md, flags);

	PKCS7_set_detached(p7, 1);

	rc = PKCS7_final(p7, data_bio, flags);
	if (!rc) {
		fprintf(stderr, "Error signing variable data\n");
		ERR_print_errors_fp(stderr);
		BIO_free_all(data_bio);
		return -1;
	}

	len = i2d_PKCS7_SIGNED(p7->d.sign, NULL);


	/* set up our auth descriptor */
	auth = talloc_size(ctx, sizeof(*auth) + len);

	auth->TimeStamp = timestamp;
	auth->AuthInfo.Hdr.dwLength = len + sizeof(auth->AuthInfo);
	auth->AuthInfo.Hdr.wRevision = 0x0200;
	auth->AuthInfo.Hdr.wCertificateType = 0x0EF1;
	auth->AuthInfo.CertType = cert_pkcs7_guid;
	tmp = auth->AuthInfo.CertData;
	i2d_PKCS7_SIGNED(p7->d.sign, &tmp);

	ctx->auth_descriptor = auth;
	ctx->auth_descriptor_len = sizeof(*auth) + len;

	BIO_free_all(data_bio);

	return 0;
}

int write_signed(struct varsign_context *ctx, int include_attrs)
{
	int fd, rc;

	fd = open(ctx->outfilename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open");
		goto err;
	}

	/* For some uses (eg, writing to the efivars filesystem), we may
	 * want to prefix the signed variable with four bytes of attribute
	 * data
	 */
	if (include_attrs) {
		rc = write_all(fd, &ctx->var_attrs, sizeof(ctx->var_attrs));
		if (!rc) {
			perror("write_all");
			goto err;
		}
	}

	/* Write the authentication descriptor */
	rc = write_all(fd, ctx->auth_descriptor, ctx->auth_descriptor_len);
	if (!rc) {
		perror("write_all");
		goto err;
	}

	/* ... and the variable data itself */
	rc = write_all(fd, ctx->data, ctx->data_len);
	if (!rc) {
		perror("write_all");
		goto err;
	}

	if (ctx->verbose) {
		size_t i = 0;

		printf("Wrote signed data:\n");
		if (include_attrs) {
			i = sizeof(ctx->var_attrs);
			printf("  [%04lx:%04zx] attrs\n", 0l, i);
		}

		printf("  [%04zx:%04x] authentication descriptor\n",
				i, ctx->auth_descriptor_len);

		printf("    [%04zx:%04zx] EFI_VAR_AUTH_2 header\n",
				i,
				sizeof(EFI_VARIABLE_AUTHENTICATION_2));

		printf("    [%04zx:%04zx] WIN_CERT_UEFI_GUID header\n",
				i + offsetof(EFI_VARIABLE_AUTHENTICATION_2,
					AuthInfo),
				sizeof(WIN_CERTIFICATE_UEFI_GUID));

		printf("    [%04zx:%04zx] WIN_CERT header\n",
				i + offsetof(EFI_VARIABLE_AUTHENTICATION_2,
					AuthInfo.Hdr),
				sizeof(WIN_CERTIFICATE));

		printf("    [%04zx:%04zx] pkcs7 data\n",
				i + offsetof(EFI_VARIABLE_AUTHENTICATION_2,
					AuthInfo.CertData),
				ctx->auth_descriptor_len -
					sizeof(EFI_VARIABLE_AUTHENTICATION_2));

		i += ctx->auth_descriptor_len;

		printf("  [%04zx:%04zx] variable data\n",
				i, i + ctx->data_len);
	}

	close(fd);
	return 0;

err:
	fprintf(stderr, "Can't write signed data to file '%s'\n",
			ctx->outfilename);
	if (fd >= 0)
		close(fd);
	return -1;

}

static void set_default_guid(struct varsign_context *ctx, const char *varname)
{
	EFI_GUID secdb_guid = EFI_IMAGE_SECURITY_DATABASE_GUID;
	EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;

	if (!strcmp(varname, "db") || !strcmp(varname, "dbx"))
		ctx->var_guid = secdb_guid;
	else
		ctx->var_guid = global_guid;
}

static struct option options[] = {
	{ "output", required_argument, NULL, 'o' },
	{ "guid", required_argument, NULL, 'g' },
	{ "attrs", required_argument, NULL, 'a' },
	{ "key", required_argument, NULL, 'k' },
	{ "cert", required_argument, NULL, 'c' },
	{ "include-attrs", no_argument, NULL, 'i' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ "engine", required_argument, NULL, 'e'},
	{ NULL, 0, NULL, 0 },
};

void usage(void)
{
	unsigned int i;

	printf("Usage: %s [options] --key <keyfile> --cert <certfile> "
			"<var-name> <var-data-file>\n"
		"Sign a blob of data for use in SetVariable().\n\n"
		"Options:\n"
		"\t--engine <eng>     use the specified engine to load the key\n"
		"\t--key <keyfile>    signing key (PEM-encoded RSA "
						"private key)\n"
		"\t--cert <certfile>  certificate (x509 certificate)\n"
		"\t--include-attrs  include attrs at beginning of output file\n"
		"\t--guid <GUID>    EFI GUID for the variable. If omitted,\n"
		"\t                  EFI_IMAGE_SECURITY_DATABASE or\n"
		"\t                  EFI_GLOBAL_VARIABLE (depending on\n"
		"\t                  <var-name>) will be used.\n"
		"\t--attr <attrs>   variable attributes. One or more of:\n",
		toolname);

	for (i = 0; i < ARRAY_SIZE(attrs); i++)
		printf("\t                     %s\n", attrs[i].name);

	printf("\t                  Separate multiple attrs with a comma,\n"
		"\t                  default is all attributes,\n"
		"\t                  TIME_BASED_AUTH... is always included.\n"
		"\t--output <file>  write signed data to <file>\n"
		"\t                  (default <var-data-file>.signed)\n");
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}

int main(int argc, char **argv)
{
	const char *guid_str, *attr_str, *varname, *engine;
	const char *keyfilename, *certfilename;
	ENGINE* e;
	UI_METHOD *ui;
	struct varsign_context *ctx;
	bool include_attrs;
	int c;

	ctx = talloc_zero(NULL, struct varsign_context);

	keyfilename = NULL;
	certfilename = NULL;
	engine = NULL;
	guid_str = NULL;
	attr_str= NULL;
	e = NULL;
	ui = NULL;
	include_attrs = false;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "o:g:a:k:c:ivVhe:", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'o':
			ctx->outfilename = optarg;
			break;
		case 'g':
			guid_str = optarg;
			break;
		case 'a':
			attr_str = optarg;
			break;
		case 'k':
			keyfilename = optarg;
			break;
		case 'c':
			certfilename = optarg;
			break;
		case 'i':
			include_attrs = true;
			break;
		case 'v':
			ctx->verbose = 1;
			break;
		case 'V':
			version();
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		case 'e':
			engine = optarg;
			break;
		}
	}

	if (argc != optind + 2) {
		usage();
		return EXIT_FAILURE;
	}

	if (!keyfilename) {
		fprintf(stderr, "No signing key specified\n");
		return EXIT_FAILURE;
	}

	if (!certfilename) {
		fprintf(stderr, "No signing certificate specified\n");
		return EXIT_FAILURE;
	}

	/* initialise openssl */
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();
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

	/* set up the variable signing context */
	varname = argv[optind];
	set_varname(ctx, varname);
	ctx->infilename = argv[optind+1];

	if (!ctx->outfilename)
		set_default_outfilename(ctx);

	if (attr_str) {
		ctx->var_attrs = parse_attrs(attr_str);
		if (ctx->var_attrs == attr_invalid)
			return EXIT_FAILURE;
	} else {
		ctx->var_attrs = default_attrs;
	}

	if (guid_str) {
		if (parse_guid(guid_str, &ctx->var_guid)) {
			fprintf(stderr, "Invalid GUID '%s'\n", guid_str);
			return EXIT_FAILURE;
		}
	} else {
		set_default_guid(ctx, varname);
	}

	if (fileio_read_file(ctx, ctx->infilename, &ctx->data, &ctx->data_len))
		return EXIT_FAILURE;

	if (engine) {
		e = setup_engine(engine, ui);
		if (!e) 
			return EXIT_FAILURE;

		ctx->key = fileio_read_engine_key(e, keyfilename, KEYFORM_PEM, ui);
	} else
		ctx->key = fileio_read_pkey(keyfilename);
	if (!ctx->key)
		return EXIT_FAILURE;

	ctx->cert = fileio_read_cert(certfilename);
	if (!ctx->cert)
		return EXIT_FAILURE;

	/* do the signing */
	if (add_auth_descriptor(ctx))
		return EXIT_FAILURE;

	/* write the resulting image */
	if (write_signed(ctx, include_attrs))
		return EXIT_FAILURE;

	if (e) {
		ENGINE_finish(e);
		ENGINE_free(e);
	}

	return EXIT_SUCCESS;
}

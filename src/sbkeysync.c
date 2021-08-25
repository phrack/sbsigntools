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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>

#include <getopt.h>

#include <ccan/list/list.h>
#include <ccan/array_size/array_size.h>
#include <ccan/talloc/talloc.h>

#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "fileio.h"
#include "efivars.h"

static struct statfs statfstype;

#define EFIVARS_MOUNTPOINT	"/sys/firmware/efi/efivars"
#define PSTORE_FSTYPE		((typeof(statfstype.f_type))0x6165676C)
#define EFIVARS_FSTYPE		((typeof(statfstype.f_type))0xde5e81e4)

#define EFI_IMAGE_SECURITY_DATABASE_GUID \
	{ 0xd719b2cb, 0x3d3a, 0x4596, \
	{ 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f } }

static const char *toolname = "sbkeysync";

static const uint32_t sigdb_attrs = EFI_VARIABLE_NON_VOLATILE |
	EFI_VARIABLE_BOOTSERVICE_ACCESS |
	EFI_VARIABLE_RUNTIME_ACCESS |
	EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
	EFI_VARIABLE_APPEND_WRITE;

struct key_database_type {
	const char	*name;
	EFI_GUID	guid;
};

struct key_database_type keydb_types[] = {
	{ "PK",  EFI_GLOBAL_VARIABLE },
	{ "KEK", EFI_GLOBAL_VARIABLE },
	{ "db",  EFI_IMAGE_SECURITY_DATABASE_GUID },
	{ "dbx", EFI_IMAGE_SECURITY_DATABASE_GUID },
};

enum keydb_type {
	KEYDB_PK = 0,
	KEYDB_KEK = 1,
	KEYDB_DB = 2,
	KEYDB_DBX = 3,
};

static const char *default_keystore_dirs[] = {
	"/etc/secureboot/keys",
	"/usr/share/secureboot/keys",
};


struct key {
	EFI_GUID			type;
	int				id_len;
	uint8_t				*id;

	char				*description;

	struct list_node		list;

	/* set for keys loaded from a filesystem keystore */
	struct fs_keystore_entry	*keystore_entry;
};

typedef int (*key_parse_func)(struct key *, uint8_t *, size_t);

struct cert_type {
	EFI_GUID	guid;
	key_parse_func	parse;
};

struct key_database {
	const struct key_database_type	*type;
	struct list_head		keys;
};

struct keyset {
	struct key_database	pk;
	struct key_database	kek;
	struct key_database	db;
	struct key_database	dbx;
};

struct fs_keystore_entry {
	const struct key_database_type	*type;
	const char			*root;
	const char			*name;
	uint8_t				*data;
	size_t				len;
	struct list_node		keystore_list;
	struct list_node		new_list;
};

struct fs_keystore {
	struct list_head	keys;
};

struct sync_context {
	const char		*efivars_dir;
	struct keyset		*filesystem_keys;
	struct keyset		*firmware_keys;
	struct fs_keystore	*fs_keystore;
	const char		**keystore_dirs;
	unsigned int		n_keystore_dirs;
	struct list_head	new_keys;
	bool			verbose;
	bool			dry_run;
	bool			set_pk;
};


#define GUID_STRLEN (8 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 12 + 1)
static void guid_to_str(const EFI_GUID *guid, char *str)
{
	snprintf(str, GUID_STRLEN,
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			guid->Data1, guid->Data2, guid->Data3,
			guid->Data4[0], guid->Data4[1],
			guid->Data4[2], guid->Data4[3],
			guid->Data4[4], guid->Data4[5],
			guid->Data4[6], guid->Data4[7]);
}

static int sha256_key_parse(struct key *key, uint8_t *data, size_t len)
{
	const unsigned int sha256_id_size = 256 / 8;
	unsigned int i;

	if (len != sha256_id_size)
		return -1;

	key->id = talloc_memdup(key, data, sha256_id_size);
	key->id_len = sha256_id_size;

	key->description = talloc_array(key, char, len * 2 + 1);
	for (i = 0; i < len; i++)
		snprintf(&key->description[i*2], 3, "%02x", data[i]);
	key->description[len*2] = '\0';

	return 0;
}

static int x509_key_parse(struct key *key, uint8_t *data, size_t len)
{
	const int description_len = 160;
	ASN1_INTEGER *serial;
	const uint8_t *tmp;
	X509 *x509;
	int rc;

	rc = -1;

	tmp = data;

	x509 = d2i_X509(NULL, &tmp, len);
	if (!x509)
		return -1;

	/* we use the X509 serial number as the key ID */
	serial = X509_get_serialNumber(x509);
	if (!serial)
		goto out;

	key->id_len = ASN1_STRING_length(serial);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	key->id = talloc_memdup(key, ASN1_STRING_data(serial), key->id_len);
#else
	key->id = talloc_memdup(key, ASN1_STRING_get0_data(serial), key->id_len);
#endif

	key->description = talloc_array(key, char, description_len);
	X509_NAME_oneline(X509_get_subject_name(x509),
			key->description, description_len);

	rc = 0;

out:
	X509_free(x509);
	return rc;
}

struct cert_type cert_types[] = {
	{ EFI_CERT_SHA256_GUID, sha256_key_parse },
	{ EFI_CERT_X509_GUID, x509_key_parse },
};

static int guidcmp(const EFI_GUID *a, const EFI_GUID *b)
{
	return memcmp(a, b, sizeof(EFI_GUID));
}

static int key_parse(struct key *key, const EFI_GUID *type,
		uint8_t *data, size_t len)
{
	char guid_str[GUID_STRLEN];
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cert_types); i++) {
		if (guidcmp(&cert_types[i].guid, type))
			continue;

		return cert_types[i].parse(key, data, len);
	}

	guid_to_str(type, guid_str);
	printf("warning: unknown signature type found:\n  %s\n",
			guid_str);
	return -1;

}

typedef int (*sigdata_fn)(EFI_SIGNATURE_DATA *, int, const EFI_GUID *, void *);

/**
 * Iterates an buffer of EFI_SIGNATURE_LISTs (at db_data, of length len),
 * and calls fn on each EFI_SIGNATURE_DATA item found.
 *
 * fn is passed the EFI_SIGNATURE_DATA pointer, and the length of the
 * signature data (including GUID header), the type of the signature list,
 * and a context pointer.
 */
static int sigdb_iterate(void *db_data, size_t len,
		sigdata_fn fn, void *arg)
{
	EFI_SIGNATURE_LIST *siglist;
	EFI_SIGNATURE_DATA *sigdata;
	unsigned int i, j;
	int rc = 0;

	if (len == 0)
		return 0;

	if (len < sizeof(*siglist))
		return -1;

	for (i = 0, siglist = db_data + i;
			i + sizeof(*siglist) <= len &&
			i + siglist->SignatureListSize > i &&
			i + siglist->SignatureListSize <= len && !rc;
			i += siglist->SignatureListSize,
			siglist = db_data + i) {

		/* ensure that the header & sig sizes are sensible */
		if (siglist->SignatureHeaderSize > siglist->SignatureListSize)
			continue;

		if (siglist->SignatureSize > siglist->SignatureListSize)
			continue;

		if (siglist->SignatureSize < sizeof(*sigdata))
			continue;

		/* iterate through the (constant-sized) signature data blocks */
		for (j = sizeof(*siglist) + siglist->SignatureHeaderSize;
				j < siglist->SignatureListSize && !rc;
				j += siglist->SignatureSize)
		{
			sigdata = (void *)(siglist) + j;

			rc = fn(sigdata, siglist->SignatureSize,
					&siglist->SignatureType, arg);

		}

	}

	return rc;
}

struct keydb_add_ctx {
	struct fs_keystore_entry *ke;
	struct key_database *kdb;
	struct keyset *keyset;
};

static int keydb_add_key(EFI_SIGNATURE_DATA *sigdata, int len,
		const EFI_GUID *type, void *arg)
{
	struct keydb_add_ctx *add_ctx = arg;
	struct key *key;
	int rc;

	key = talloc(add_ctx->keyset, struct key);

	rc = key_parse(key, type, sigdata->SignatureData,
			len - sizeof(*sigdata));

	if (rc) {
		talloc_free(key);
		return 0;
	}
	key->keystore_entry = add_ctx->ke;
	key->type = *type;

	/* add a reference to the keystore entry: we don't want it to be
	 * deallocated if the keystore is deallocated before the
	 * struct key. */
	if (key->keystore_entry)
		talloc_reference(key, key->keystore_entry);

	list_add(&add_ctx->kdb->keys, &key->list);

	return 0;
}

static int read_firmware_keydb(struct sync_context *ctx,
		struct key_database *kdb)
{
	struct keydb_add_ctx add_ctx;
	char guid_str[GUID_STRLEN];
	char *filename;
	uint8_t *buf;
	int rc = -1;
	size_t len;

	add_ctx.keyset = ctx->firmware_keys;
	add_ctx.kdb = kdb;
	add_ctx.ke = NULL;

	guid_to_str(&kdb->type->guid, guid_str);

	filename = talloc_asprintf(ctx->firmware_keys, "%s/%s-%s",
			ctx->efivars_dir, kdb->type->name, guid_str);

	buf = NULL;
	rc = fileio_read_file_noerror(ctx->firmware_keys, filename, &buf, &len);
	if (rc)
		goto out;

	/* efivars files start with a 32-bit attribute block */
	if (len < sizeof(uint32_t))
		goto out;

	buf += sizeof(uint32_t);
	len -= sizeof(uint32_t);

	rc = 0;
	sigdb_iterate(buf, len, keydb_add_key, &add_ctx);

out:
	if (rc)
		talloc_free(buf);
	talloc_free(filename);

	return rc;
}

static void __attribute__((format(printf, 2, 3))) print_keystore_key_error(
		struct fs_keystore_entry *ke, const char *fmt, ...)
{
	char *errstr;
	va_list ap;

	va_start(ap, fmt);
	errstr = talloc_vasprintf(ke, fmt, ap);

	fprintf(stderr, "Invalid key %s/%s\n - %s\n", ke->root, ke->name,
			errstr);

	talloc_free(errstr);
	va_end(ap);
}

static int read_filesystem_keydb(struct sync_context *ctx,
		struct key_database *kdb)
{
	EFI_GUID cert_type_pkcs7 = EFI_CERT_TYPE_PKCS7_GUID;
	EFI_VARIABLE_AUTHENTICATION_2 *auth;
	struct keydb_add_ctx add_ctx;
	struct fs_keystore_entry *ke;
	int rc;

	add_ctx.keyset = ctx->filesystem_keys;
	add_ctx.kdb = kdb;

	list_for_each(&ctx->fs_keystore->keys, ke, keystore_list) {
		unsigned int len;
		void *buf;

		if (ke->len == 0)
			continue;

		if (ke->type != kdb->type)
			continue;

		/* parse the three data structures:
		 *  EFI_VARIABLE_AUTHENTICATION_2 token
		 *  EFI_SIGNATURE_LIST
		 *  EFI_SIGNATURE_DATA
		 * ensuring that we have enough data for each
		 */

		buf = ke->data;
		len = ke->len;

		if (len < sizeof(*auth)) {
			print_keystore_key_error(ke, "does not contain an "
				"EFI_VARIABLE_AUTHENTICATION_2 descriptor");
			continue;
		}

		auth = buf;

		if (guidcmp(&auth->AuthInfo.CertType, &cert_type_pkcs7)) {
			print_keystore_key_error(ke, "unknown cert type");
			continue;
		}

		if (auth->AuthInfo.Hdr.dwLength > len) {
			print_keystore_key_error(ke,
					"invalid WIN_CERTIFICATE length");
			continue;
		}

		/* the dwLength field includes the size of the WIN_CERTIFICATE,
		 * but not the other data in the EFI_VARIABLE_AUTHENTICATION_2
		 * descriptor */
		buf += sizeof(*auth) - sizeof(auth->AuthInfo) +
			auth->AuthInfo.Hdr.dwLength;
		len -= sizeof(*auth) - sizeof(auth->AuthInfo) +
			auth->AuthInfo.Hdr.dwLength;

		add_ctx.ke = ke;
		rc = sigdb_iterate(buf, len, keydb_add_key, &add_ctx);
		if (rc) {
			print_keystore_key_error(ke, "error parsing "
					"EFI_SIGNATURE_LIST");
			continue;
		}

	}

	return 0;
}

static int read_keysets(struct sync_context *ctx)
{
	read_firmware_keydb(ctx, &ctx->firmware_keys->pk);
	read_firmware_keydb(ctx, &ctx->firmware_keys->kek);
	read_firmware_keydb(ctx, &ctx->firmware_keys->db);
	read_firmware_keydb(ctx, &ctx->firmware_keys->dbx);

	read_filesystem_keydb(ctx, &ctx->filesystem_keys->pk);
	read_filesystem_keydb(ctx, &ctx->filesystem_keys->kek);
	read_filesystem_keydb(ctx, &ctx->filesystem_keys->db);
	read_filesystem_keydb(ctx, &ctx->filesystem_keys->dbx);

	return 0;
}

static int check_pk(struct sync_context *ctx)
{
	struct key *key;
	int i = 0;

	list_for_each(&ctx->filesystem_keys->pk.keys, key, list)
		i++;

	return (i <= 1) ? 0 : 1;
}

static void print_keyset(struct keyset *keyset, const char *name)
{
	struct key_database *kdbs[] =
		{ &keyset->pk, &keyset->kek, &keyset->db, &keyset->dbx };
	struct key *key;
	unsigned int i;

	printf("%s keys:\n", name);

	for (i = 0; i < ARRAY_SIZE(kdbs); i++) {
		printf("  %s:\n", kdbs[i]->type->name);

		list_for_each(&kdbs[i]->keys, key, list) {
			printf("    %s\n", key->description);
			if (key->keystore_entry)
				printf("     from %s/%s\n",
						key->keystore_entry->root,
						key->keystore_entry->name);
		}
	}
}

static int check_efivars_mount(const char *mountpoint)
{
	struct statfs statbuf;
	int rc;

	rc = statfs(mountpoint, &statbuf);
	if (rc)
		return -1;

	if (statbuf.f_type != EFIVARS_FSTYPE && statbuf.f_type != PSTORE_FSTYPE)
		return -1;

	return 0;
}

static int keystore_entry_read(struct fs_keystore_entry *ke)
{
	const char *path;
	int rc;

	path = talloc_asprintf(ke, "%s/%s", ke->root, ke->name);

	rc = fileio_read_file(ke, path, &ke->data, &ke->len);

	talloc_free(path);

	return rc;
}

static bool keystore_contains_file(struct fs_keystore *keystore,
		const char *filename)
{
	struct fs_keystore_entry *ke;

	list_for_each(&keystore->keys, ke, keystore_list) {
		if (!strcmp(ke->name, filename))
			return true;
	}

	return false;
}

static int update_keystore(struct fs_keystore *keystore, const char *root)
{
	struct fs_keystore_entry *ke;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(keydb_types); i++) {
		const char *filename, *dirname;
		struct dirent *dirent;
		DIR *dir;

		dirname = talloc_asprintf(keystore, "%s/%s", root,
					keydb_types[i].name);

		dir = opendir(dirname);
		if (!dir)
			continue;

		for (dirent = readdir(dir); dirent; dirent = readdir(dir)) {

			if (dirent->d_name[0] == '.')
				continue;

			filename = talloc_asprintf(dirname, "%s/%s",
					keydb_types[i].name,
					dirent->d_name);

			if (keystore_contains_file(keystore, filename))
				continue;

			ke = talloc(keystore, struct fs_keystore_entry);
			ke->name = filename;
			ke->root = root;
			ke->type = &keydb_types[i];
			talloc_steal(ke, ke->name);

			if (keystore_entry_read(ke))
				talloc_free(ke);
			else
				list_add(&keystore->keys, &ke->keystore_list);
		}

		closedir(dir);
		talloc_free(dirname);
	}

	return 0;
}

static int read_keystore(struct sync_context *ctx)
{
	struct fs_keystore *keystore;
	unsigned int i;

	keystore = talloc(ctx, struct fs_keystore);
	list_head_init(&keystore->keys);

	for (i = 0; i < ctx->n_keystore_dirs; i++) {
		update_keystore(keystore, ctx->keystore_dirs[i]);
	}

	ctx->fs_keystore = keystore;

	return 0;
}

static void print_keystore(struct fs_keystore *keystore)
{
	struct fs_keystore_entry *ke;

	printf("Filesystem keystore:\n");

	list_for_each(&keystore->keys, ke, keystore_list)
		printf("  %s/%s [%zd bytes]\n", ke->root, ke->name, ke->len);
}

static int key_cmp(struct key *a, struct key *b)
{
	if (a->id_len != b->id_len)
		return a->id_len - b->id_len;

	return memcmp(a->id, b->id, a->id_len);
}

/**
 * Finds the set-difference of the filesystem and firmware keys, and
 * populates ctx->new_keys with the keystore_entries that should be
 * inserted into firmware
 */
static int find_new_keys(struct sync_context *ctx)
{
	struct {
		struct key_database *fs_kdb, *fw_kdb;
	} kdbs[] = {
		{ &ctx->filesystem_keys->pk,  &ctx->firmware_keys->pk },
		{ &ctx->filesystem_keys->kek, &ctx->firmware_keys->kek },
		{ &ctx->filesystem_keys->db,  &ctx->firmware_keys->db },
		{ &ctx->filesystem_keys->dbx, &ctx->firmware_keys->dbx },
	};
	unsigned int i;
	int n = 0;

	for (i = 0; i < ARRAY_SIZE(kdbs); i++ ) {
		struct fs_keystore_entry *ke;
		struct key *fs_key, *fw_key;
		bool found;

		list_for_each(&kdbs[i].fs_kdb->keys, fs_key, list) {
			found = false;
			list_for_each(&kdbs[i].fw_kdb->keys, fw_key, list) {
				if (!key_cmp(fs_key, fw_key)) {
					found = true;
					break;
				}
			}
			if (found)
				continue;

			/* add the keystore entry if it's not already present */
			found = false;
			list_for_each(&ctx->new_keys, ke, new_list) {
				if (fs_key->keystore_entry == ke) {
					found = true;
					break;
				}
			}

			if (found)
				continue;

			list_add(&ctx->new_keys,
					&fs_key->keystore_entry->new_list);
			n++;
		}
	}

	return n;
}

static void print_new_keys(struct sync_context *ctx)
{
	struct fs_keystore_entry *ke;

	printf("New keys in filesystem:\n");

	list_for_each(&ctx->new_keys, ke, new_list)
		printf(" %s/%s\n", ke->root, ke->name);
}

static int insert_key(struct sync_context *ctx, struct fs_keystore_entry *ke)
{
	char guid_str[GUID_STRLEN];
	char *efivars_filename;
	unsigned int buf_len;
	uint8_t *buf;
	int fd, rc;

	fd = -1;
	rc = -1;

	if (ctx->verbose)
		printf("Inserting key update %s/%s into %s\n",
				ke->root, ke->name, ke->type->name);

	/* we create a contiguous buffer of attributes & key data, so that
	 * we write to the efivars file in a single syscall */
	buf_len = sizeof(sigdb_attrs) + ke->len;
	buf = talloc_array(ke, uint8_t, buf_len);
	memcpy(buf, &sigdb_attrs, sizeof(sigdb_attrs));
	memcpy(buf + sizeof(sigdb_attrs), ke->data, ke->len);

	guid_to_str(&ke->type->guid, guid_str);

	efivars_filename = talloc_asprintf(ke, "%s/%s-%s", ctx->efivars_dir,
						ke->type->name, guid_str);

	fd = open(efivars_filename, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		fprintf(stderr,	"Can't create key file %s: %s\n",
				efivars_filename, strerror(errno));
		goto out;
	}

	rc = write(fd, buf, buf_len);
	if (rc <= 0) {
		fprintf(stderr, "Error writing key update: %s\n",
				strerror(errno));
		goto out;
	}

	if (rc != (int)buf_len) {
		fprintf(stderr, "Partial write during key update: "
				"wrote %d bytes, expecting %d\n",
				rc, buf_len);
		goto out;
	}

	rc = 0;

out:
	if (fd >= 0)
		close(fd);
	talloc_free(efivars_filename);
	talloc_free(buf);
	if (rc)
		fprintf(stderr, "Error syncing keystore file %s/%s\n",
				ke->root, ke->name);
	return rc;
}

static int insert_new_keys(struct sync_context *ctx)
{
	struct fs_keystore_entry *ke, *ke_pk;
	int pks, rc;

	rc = 0;
	pks = 0;
	ke_pk = NULL;

	list_for_each(&ctx->new_keys, ke, new_list) {

		/* we handle PK last */
		if (ke->type == &keydb_types[KEYDB_PK]) {
			ke_pk = ke;
			pks++;
			continue;
		}

		if (insert_key(ctx, ke))
			rc = -1;
	}

	if (rc)
		return rc;

	if (pks == 0 || !ctx->set_pk)
		return 0;

	if (pks > 1) {
		fprintf(stderr, "Skipping PK update due to mutiple PKs\n");
		return -1;
	}

	rc = insert_key(ctx, ke_pk);

	return rc;
}

static struct keyset *init_keyset(struct sync_context *ctx)
{
	struct keyset *keyset;

	keyset = talloc(ctx, struct keyset);

	list_head_init(&keyset->pk.keys);
	keyset->pk.type = &keydb_types[KEYDB_PK];

	list_head_init(&keyset->kek.keys);
	keyset->kek.type = &keydb_types[KEYDB_KEK];

	list_head_init(&keyset->db.keys);
	keyset->db.type = &keydb_types[KEYDB_DB];

	list_head_init(&keyset->dbx.keys);
	keyset->dbx.type = &keydb_types[KEYDB_DBX];

	return keyset;
}

static struct option options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ "efivars-path", required_argument, NULL, 'e' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "dry-run", no_argument, NULL, 'n' },
	{ "pk", no_argument, NULL, 'p' },
	{ "no-default-keystores", no_argument, NULL, 'd' },
	{ "keystore", required_argument, NULL, 'k' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s [options]\n"
		"Update EFI key databases from the filesystem\n"
		"\n"
		"Options:\n"
		"\t--efivars-path <dir>  Path to efivars mountpoint\n"
		"\t                       (or regular directory for testing)\n"
		"\t--verbose             Print verbose progress information\n"
		"\t--dry-run             Don't update firmware key databases\n"
		"\t--pk                  Set PK\n"
		"\t--keystore <dir>      Read keys from <dir>/{db,dbx,KEK}/*\n"
		"\t                       (can be specified multiple times,\n"
		"\t                       first dir takes precedence)\n"
		"\t--no-default-keystores\n"
		"\t                      Don't read keys from the default\n"
		"\t                       keystore dirs\n",
		toolname);
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}

static void add_keystore_dir(struct sync_context *ctx, const char *dir)
{
	ctx->keystore_dirs = talloc_realloc(ctx, ctx->keystore_dirs,
			const char *, ++ctx->n_keystore_dirs);

	ctx->keystore_dirs[ctx->n_keystore_dirs - 1] =
				talloc_strdup(ctx->keystore_dirs, dir);
}

int main(int argc, char **argv)
{
	bool use_default_keystore_dirs;
	struct sync_context *ctx;
	int rc;

	use_default_keystore_dirs = true;
	ctx = talloc_zero(NULL, struct sync_context);
	list_head_init(&ctx->new_keys);
	rc = EXIT_SUCCESS;

	for (;;) {
		int idx, c;
		c = getopt_long(argc, argv, "e:dpkvhV", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'e':
			ctx->efivars_dir = optarg;
			break;
		case 'd':
			use_default_keystore_dirs = false;
			break;
		case 'k':
			add_keystore_dir(ctx, optarg);
			break;
		case 'p':
			ctx->set_pk = true;
			break;
		case 'v':
			ctx->verbose = true;
			break;
		case 'n':
			ctx->dry_run = true;
			break;
		case 'V':
			version();
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		}
	}

	if (argc != optind) {
		usage();
		return EXIT_FAILURE;
	}

	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();
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

	ctx->filesystem_keys = init_keyset(ctx);
	ctx->firmware_keys = init_keyset(ctx);

	if (!ctx->efivars_dir) {
		ctx->efivars_dir = EFIVARS_MOUNTPOINT;
		if (check_efivars_mount(ctx->efivars_dir)) {
			fprintf(stderr, "Can't access efivars filesystem "
					"at %s, aborting\n", ctx->efivars_dir);
			return EXIT_FAILURE;
		}
	}

	if (use_default_keystore_dirs) {
		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(default_keystore_dirs); i++)
			add_keystore_dir(ctx, default_keystore_dirs[i]);
	}


	read_keystore(ctx);

	if (ctx->verbose)
		print_keystore(ctx->fs_keystore);

	read_keysets(ctx);
	if (ctx->verbose) {
		print_keyset(ctx->firmware_keys, "firmware");
		print_keyset(ctx->filesystem_keys, "filesystem");
	}

	if (check_pk(ctx))
		fprintf(stderr, "WARNING: multiple PKs found in filesystem\n");

	find_new_keys(ctx);

	if (ctx->verbose)
		print_new_keys(ctx);

	if (!ctx->dry_run && insert_new_keys(ctx))
		rc = EXIT_FAILURE;

	talloc_free(ctx);

	return rc;
}

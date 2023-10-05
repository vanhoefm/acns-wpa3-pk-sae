#include <time.h>

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/base64.h"
#include "crypto/crypto.h"
#include "common/sae.h"

#define BYTES(x) ((x + 7) / 8)

/** If P_D is not defined that assume everything is defined through make */
#ifndef P_D

/** Fingerprint length. Can be arbitrary number of bits. */
#define P_OUT	24
/** Number of zero bits to secure fingerprint (normally 24 or 40).  Can be arbitrary number of bits. */
#define P_SEC	8
/** Number of zero bits in distinguished points. Can be an arbitrary number of bits. */
#define P_D	5
/** Number of colors used in each table. */
#define P_C	8
/** Number of chains in a table. Can be at most 2^16. */
#define P_M	1024
/** Number of independent tables to generate. */
#define P_R	64

#endif /** End make check */

/** Maximum length of a subchain. After this we abort to avoid cycles. */
#define T_MAX	(1 << (P_D + 3))

/**
 * Assumptions made:
 * - At most 2^16 tables
 * - At most 2^16 colors
 */

/** Output length of PKHash. Includes P_SEC and P_D bits. */
#define P_BYTES_OUT		BYTES(P_SEC + P_OUT)

//#define TEST_LOOKUP
//#define NO_RAND_SIG

#define STATUS	0
#define VERBOSE	1
#define DEBUG	2

static int output_level = STATUS;

struct chain_t {
	u8 start_sig[P_BYTES_OUT];
	u8 end_sig[P_BYTES_OUT];
	// FIXME: This can probably be removed. Turn into a define?
	u32 lens[P_C];
	u32 tot_len;
};

struct table_t {
	int index;
	struct chain_t *chains[P_M];
};

struct stats_t {
	unsigned long num_duplicates;
	unsigned long num_tests;
	unsigned long num_false_alarms;
	unsigned long num_pkhash_calls;
	unsigned long num_found;
	unsigned long num_null_chains;
	unsigned long num_lookup_dp_fails;
	unsigned long num_lookups;
} stats;

void hex_dump(int level, const void *arg, size_t len, const char *prefix)
{
	if (level > output_level)
		return;

	u8* buff = (u8*)arg;
	if (prefix)
		printf("%s", prefix);

	for (size_t i = 0; i < len; i++)
		printf("%02X ", buff[i]);
	printf("\n");
}


int starts_with_zero_bits(u8 *array, int num_bits)
{
	int i;

	// Leading bytes must always be zero
	for (i = 0; i < (num_bits / 8); ++i)
		if (array[i] != 0)
			return 0;

	// Remaining bits must also be zero
	int remaining_bits = ( array[i] << (8 - (num_bits % 8)) ) & 0xFF;
	return remaining_bits == 0;
}


int is_distinguished(u8 sig[P_BYTES_OUT])
{
	return starts_with_zero_bits(sig, P_SEC + P_D);
}


void pkhash(size_t hash_len, char *ssid, size_t ssid_len, u8 modifier[16], struct wpabuf *pub, u8 hash[P_BYTES_OUT])
{
	unsigned long long i;
	size_t data_len;
	u8 data[1024], fullhash[hash_len];
	u8 *m = NULL;

	stats.num_pkhash_calls += 1;

	data_len = ssid_len + SAE_PK_M_LEN + wpabuf_len(pub);
	memset(data, 0, data_len);

	memcpy(data, ssid, ssid_len);
	m = data + ssid_len;
	memcpy(m, modifier, 16);
	memcpy(m + SAE_PK_M_LEN, wpabuf_head(pub), wpabuf_len(pub));

	for (i = 0;; i++)
	{
		if (sae_hash(hash_len, data, data_len, fullhash) < 0)
		{
			fprintf(stderr, "Hash failed\n");
			exit(1);
		}

		if (starts_with_zero_bits(fullhash, P_SEC))
			break;

		// Increments the counter in big endian (least significant byte
		// is located at SAE_PK_M_LEN - 1).
		inc_byte_array(m, SAE_PK_M_LEN);
	}

	memcpy(hash, fullhash, P_BYTES_OUT);
}


#ifdef NO_RAND_SIG
static u8 counter[P_BYTES_OUT] = {0};
#endif

void read_random(u8 *buffer, size_t len)
{
	FILE *fp = fopen("/dev/urandom", "rb");
	if (fp == NULL) {
		fprintf(stderr, "Error opening /dev/urandom\n");
		exit(1);
	}
	if (fread(buffer, len, 1, fp) != 1) {
		fprintf(stderr, "Error reading from /dev/urandom\n");
		exit(1);
	}
	fclose(fp);
}

void rand_sig(u8 sig[P_BYTES_OUT])
{
#ifndef NO_RAND_SIG
	// Generate random starting point
	read_random(sig, P_BYTES_OUT);

	// Set starting zero bits
	for (int i = 0; i < (P_SEC / 8); ++i)
		sig[i] = 0;
	sig[P_SEC / 8] &= (0xff << (P_SEC % 8));
#else
	memcpy(sig, counter, P_BYTES_OUT);
	inc_byte_array(counter, P_BYTES_OUT);
#endif
}

void reset_rand_sig(time_t init_rand)
{
#ifndef NO_RAND_SIG
	srand(init_rand);
#else
	memset(counter, 0, P_BYTES_OUT);
#endif
}


/**
 * @param table_idx	Table index
 * @param color		Color to use
 * @param sig		The previous digest output (i.e. password signature)
 * @param modifier	The resulting modifier to use as the next input in PKHash
 */
void reduce(int table_idx, int color, u8 sig[P_BYTES_OUT], u8 modifier[16])
{
	memset(modifier, 0, 16);

	// Simplify by assuming we have at most 2^16 tables
	modifier[0] = table_idx / 256;
	modifier[1] = table_idx % 256;
	// Simplify by assuming we have at most 2^16 colors
	modifier[2] = color / 256;
	modifier[3] = color % 256;

	// After this there is always enough space left
	memcpy(modifier + 4, sig, P_BYTES_OUT);
}


int hash_to_distinguished_point(int table_idx, int color, size_t hash_len, char *ssid, size_t ssid_len, struct wpabuf *pub, u8 sig[P_BYTES_OUT])
{
	u8 modifier[16] = {0};
	unsigned long long i;

	// Reduce and apply hash until we have a distinguished point
	for (i = 0; i < T_MAX; ++i)
	{
		// Reduce previous signature output to new input
		reduce(table_idx, color, sig, modifier);

		// Calculate the PKHASH
		pkhash(hash_len, ssid, ssid_len, modifier, pub, sig);
		hex_dump(DEBUG, sig, P_BYTES_OUT, "sig: ");

		// Check if we have a distinguished point
		if (is_distinguished(sig))
			break;
	}

	// Return True if a distinguished point was found
	if (i == T_MAX)
		return -1;
	else
		return i;
}


int find_in_chain(int table_idx, size_t hash_len, char *ssid, size_t ssid_len, struct wpabuf *pub, struct chain_t *chain, u8 to_find[P_BYTES_OUT])
{
	u8 modifier[16] = {0};
	u8 sig[P_BYTES_OUT];
	unsigned long long i;

	memcpy(sig, chain->start_sig, P_BYTES_OUT);

	for (int color = 0; color < P_C; ++color)
	{
		// Reduce and apply hash until we have a distinguished point
		for (i = 0; i < T_MAX; ++i)
		{
			// Reduce previous signature output to new input
			reduce(table_idx, color, sig, modifier);

			// Calculate the PKHASH
			pkhash(hash_len, ssid, ssid_len, modifier, pub, sig);
			hex_dump(DEBUG, sig, P_BYTES_OUT, "sig: ");

			if (memcmp(sig, to_find, P_BYTES_OUT) == 0) {
				fprintf(stderr, "Found in table %d color %d\n", table_idx, color);
				return 1;
			}

			// Check if we have a distinguished point
			if (is_distinguished(sig))
				break;
		}

		if (i == T_MAX) {
			fprintf(stderr, "INTERNAL ERROR: T_MAX reached in find_in_chain. Len should be %d.\n", chain->lens[color]);
			fprintf(stderr, "\tTable %d color %d\n", table_idx, color);

			hex_dump(VERBOSE, chain->start_sig, P_BYTES_OUT, "\tStarting point: ");

			exit(-1);
		}
	}

	return 0;
}


struct chain_t * create_chain(int table_idx, size_t hash_len, char *ssid, size_t ssid_len, struct wpabuf *pub)
{
	struct chain_t *chain = malloc(sizeof(struct chain_t));
	u8 sig[P_BYTES_OUT];
	u32 tot_len = 0;

	// Generate random starting point
	rand_sig(chain->start_sig);
	hex_dump(VERBOSE, chain->start_sig, P_BYTES_OUT, "\tStarting point: ");

	memcpy(sig, chain->start_sig, P_BYTES_OUT);

	// Each chain consists of a number of colors
	for (int color = 0; color < P_C; color++)
	{
		// Reduce and apply hash until we have a distinguished point
		int len = hash_to_distinguished_point(table_idx, color, hash_len, ssid, ssid_len, pub, sig);
		if (len < 0) {
			free(chain);
			return NULL;
		}
		chain->lens[color] = len;
		tot_len += len;
	}

	memcpy(chain->end_sig, sig, P_BYTES_OUT);
	hex_dump(VERBOSE, chain->end_sig, P_BYTES_OUT, "\tEnd point     : ");
	chain->tot_len = tot_len;

	return chain;
}


struct table_t * create_table(int table_idx, size_t hash_len, char *ssid, size_t ssid_len, struct wpabuf *pub)
{
	struct table_t *table;
	struct chain_t *chain;
	int i;

	table = malloc(sizeof(*table));
	if (table == NULL) {
		printf("malloc failed\n");
		exit(0);
	}

	table->index = table_idx;
	for (i = 0; i < P_M; ++i)
	{
		chain = create_chain(table->index, hash_len, ssid, strlen(ssid), pub);

		if (chain == NULL) {
			stats.num_null_chains += 1;
			table->chains[i] = chain;
			continue;
		}

		for (int j = 0; j < i; ++j)
		{
			struct chain_t *other = table->chains[j];
			if (other == NULL)
				continue;

			// If we have the same endpoint, one of the chains needs to go	
			if (memcmp(other->end_sig, chain->end_sig, P_BYTES_OUT) == 0)
			{
				stats.num_duplicates += 1;

				// MATHY TODO FIXME XXX: Is this still the correct behaviour?
				if (other->tot_len > chain->tot_len)
				{
					// Once we found a longer one, discard this chain
					free(chain);
					chain = NULL;
					break;
				}
				else
				{
					// Remove everything that is shorter
					free(other);
					table->chains[j] = NULL;
				}
			}
		}

		table->chains[i] = chain;
	}

	return table;
}


int lookup_in_table(struct table_t *table, size_t hash_len, char *ssid, size_t ssid_len, struct wpabuf *pub, u8 sig[P_BYTES_OUT])
{
	u8 sig_dp[P_BYTES_OUT];

	// We start with the last color, 
	for (int color_start = P_C - 1; color_start >= 0; color_start--)
	{
		int finding_dp_failed = 0;
		
		// Hash sig until we get a distinguished point
		memcpy(sig_dp, sig, P_BYTES_OUT);

		// Keep hashing until we get the end point
		for (int color = color_start; color < P_C; ++color)
		{
			if (hash_to_distinguished_point(table->index, color, hash_len, ssid, ssid_len, pub, sig_dp) < 0) {
				finding_dp_failed = 1;
				break;
			}
		}

		// If we couldn't hash to a distinguished point (possible cycle) then this starting color
		// will not lead to a solution. So skip this starting color position.
		if (finding_dp_failed) {
			stats.num_lookup_dp_fails += 1;
			continue;
		}

		// Look up the distinguished point --- TODO XXX implement using binary search
		hex_dump(DEBUG, sig_dp, P_BYTES_OUT, "Distinguished: ");
		stats.num_lookups++;
		for (int i = 0; i < P_M; ++i)
		{
			if (table->chains[i] == NULL)
				continue;

			hex_dump(DEBUG, table->chains[i]->start_sig, P_BYTES_OUT, "Starting sig    : ");
			hex_dump(DEBUG, table->chains[i]->end_sig, P_BYTES_OUT, "Distingished sig: ");
			if (memcmp(table->chains[i]->end_sig, sig_dp, P_BYTES_OUT) != 0)
				continue;

			// Find_in_chain goes through all the colors because we cannot start in the middle,
			// have to start from scratch.
			if (find_in_chain(table->index, hash_len, ssid, ssid_len, pub, table->chains[i], sig)) {
				stats.num_found += 1;
				return 1;
			} else
				stats.num_false_alarms += 1;
		}
	}

	return 0;
}


int lookup(struct table_t **tables, size_t hash_len, char *ssid, size_t ssid_len, struct wpabuf *pub, u8 sig[P_BYTES_OUT])
{
	for (int i = 0; i < P_R; ++i)
	{
		if (tables[i] == NULL) {
			printf("Null table?!\n");
			exit(0);
		}
		if (lookup_in_table(tables[i], hash_len, ssid, ssid_len, pub, sig))
			return 1;
	}

	return 0;
}


void write_stats()
{
	char expname[1024] = {0};
	char filename[1024] = {0};

	sprintf(expname, "rainbow_%ld_%d_%d_%d_%d", time(NULL), P_D, P_C, P_M, P_R);
	sprintf(filename, "%s.json", expname);

	FILE *fp = fopen(filename, "w");

	fprintf(fp, "{\n");
	fprintf(fp, "\t\"P_OUT\": %d,\n", P_OUT);
	fprintf(fp, "\t\"P_SEC\": %d,\n", P_SEC);
	fprintf(fp, "\t\"P_D\": %d,\n", P_D);
	fprintf(fp, "\t\"P_C\": %d,\n", P_C);
	fprintf(fp, "\t\"P_M\": %d,\n", P_M);
	fprintf(fp, "\t\"P_R\": %d,\n", P_R);
	fprintf(fp, "\t\"T_MAX\": %d,\n", T_MAX);
	fprintf(fp, "\t\"P_BYTES_OUT\": %d,\n", P_BYTES_OUT);
	fprintf(fp, "\t\"num_duplicates\": %ld,\n", stats.num_duplicates);
	fprintf(fp, "\t\"num_tests\": %ld,\n", stats.num_tests);
	fprintf(fp, "\t\"num_found\": %ld,\n", stats.num_found);
	fprintf(fp, "\t\"num_false_alarms\": %ld,\n", stats.num_false_alarms);
	fprintf(fp, "\t\"num_pkhash_calls\": %ld,\n", stats.num_pkhash_calls);
	fprintf(fp, "\t\"num_null_chains\": %ld,\n", stats.num_null_chains);
	fprintf(fp, "\t\"num_lookup_dp_fails\": %ld,\n", stats.num_lookup_dp_fails);
	fprintf(fp, "\t\"num_lookups\": %ld\n", stats.num_lookups);
	fprintf(fp, "}\n");

	fclose(fp);
}


int main(int argc, char *argv[])
{
	char *der = NULL, *ssid;
	size_t der_len;
	struct crypto_ec_key *key = NULL;
	struct wpabuf *pub = NULL;
	int sec;
	int ret = -1;
	int group;
	size_t hash_len, ssid_len;

	output_level = STATUS;

	wpa_debug_level = MSG_INFO;
	if (os_program_init() < 0)
		goto fail;

	if (argc != 4) {
		fprintf(stderr,
			"usage: sae_pk_gen <DER ECPrivateKey file> <Sec:3|5> <SSID>\n");
		goto fail;
	}

	sec = atoi(argv[2]);
	if (sec != 3 && sec != 5) {
		fprintf(stderr,
			"Invalid Sec value (allowed values: 3 and 5)\n");
		goto fail;
	}

	der = os_readfile(argv[1], &der_len);
	if (!der) {
		fprintf(stderr, "Could not read %s: %s\n",
			argv[1], strerror(errno));
		goto fail;
	}

	key = crypto_ec_key_parse_priv((u8 *) der, der_len);
	if (!key) {
		fprintf(stderr, "Could not parse ECPrivateKey\n");
		goto fail;
	}

	pub = crypto_ec_key_get_subject_public_key(key);
	if (!pub) {
		fprintf(stderr, "Failed to build SubjectPublicKey\n");
		goto fail;
	}

	group = crypto_ec_key_group(key);
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

	ssid = argv[3];
	ssid_len = strlen(ssid);

	// Create the precomputed tables
	printf("Start: %ld\n", time(NULL));
	memset(&stats, 0, sizeof(stats));
	time_t init_rand = time(NULL);
	srand(init_rand);
	struct table_t *tables[P_R];
	for (int i = 0; i < P_R; ++i)
	{
		tables[i] = create_table(i, hash_len, ssid, ssid_len, pub);
		printf("Created table %d/%d. Duplicate chains over all tables: %lu\n", i, P_R, stats.num_duplicates);
	}

	printf("Table done at: %ld\n", time(NULL));
	printf("Duplicate chains: %lu\n", stats.num_duplicates);

	printf("---\n");

#ifdef TEST_LOOKUP
	/** Make it so we will look up known elements */
	reset_rand_sig(init_rand);
	u8 sig[P_BYTES_OUT];
	for (int i = 0; i < 0; ++i)
		rand_sig(sig);
#endif

	memset(&stats, 0, sizeof(stats));
	stats.num_tests = 400;

	for (unsigned long i = 0; i < stats.num_tests; ++i)
	{
		u8 sig[P_BYTES_OUT];
		rand_sig(sig);

#ifdef TEST_LOOKUP
		/** Make it so we will look up known elements */
		u8 modifier[16] = {0};
		// Reduce previous signature output to new input
		reduce(0, 0, sig, modifier);

		// Calculate the PKHASH
		pkhash(hash_len, ssid, ssid_len, modifier, pub, sig);
#endif

		printf("Trying to look up random sig (%lu/%lu)\n", i, stats.num_tests);
		hex_dump(VERBOSE, sig, P_BYTES_OUT, "Looking for  : ");
		lookup(tables, hash_len, ssid, ssid_len, pub, sig);
	}

	printf("Tests done at: %ld\n", time(NULL));
	printf("---\n");
	printf("Out of %lu lookups:\n", stats.num_tests);
	printf("- Passwords found             : %lu\n", stats.num_found);
	printf("- False alarms                : %lu\n", stats.num_false_alarms);
	printf("- Tot pkhash calls            : %lu\n", stats.num_pkhash_calls);
	printf("- Tot null chains             : %lu\n", stats.num_null_chains);
	printf("- DP hash fails during lookup : %lu\n", stats.num_lookup_dp_fails);
	printf("- Total no. of table lookups  : %lu\n", stats.num_lookups);

	write_stats();

	ret = 0;
fail:
	os_free(der);
	wpabuf_free(pub);
	crypto_ec_key_deinit(key);

	os_program_deinit();

	return ret;
}

#include <time.h>

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/base64.h"
#include "crypto/crypto.h"
#include "common/sae.h"

#define BYTES(x) ((x) / 8)

/** Must be multiple of 8 */
#define P_OUT	24
/** Must be multiple of 8 */
#define P_SEC	8
/** Must be multiple of 8 */
#define P_D		8
/** Can be at most 2^16 - otherwise the reduce function has to be updated */
#define P_M		512
#define P_R		128
#define T_MAX	(1 << (P_D + 3))

#define P_BYTES_OUT		BYTES(P_OUT)
#define P_BYTES_SEC		BYTES(P_SEC)
#define P_BYTES_D		BYTES(P_D)

//#define TEST_LOOKUP

struct chain_t {
	u8 start_sig[P_BYTES_OUT];
	u8 end_sig[P_BYTES_OUT];
	u16 len;
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

void hex_dump(const void *arg, size_t len, const char *prefix)
{
	u8* buff = (u8*)arg;
	if (prefix)
		printf("%s", prefix);

	for (size_t i = 0; i < len; i++)
		printf("%02X ", buff[i]);
	printf("\n");
}


void pkhash(size_t hash_len, char *ssid, size_t ssid_len, u8 modifier[16], struct wpabuf *pub, u8 hash[P_BYTES_OUT])
{
	unsigned long long i;
	size_t data_len;
	u8 data[1024], fullhash[hash_len];
	u8 *m = NULL;
	int j;

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

		for (j = 0; j < P_BYTES_SEC; ++j)
			if (fullhash[j] != 0)
				break;
		if (j == P_BYTES_SEC)
			break;
				
		inc_byte_array(m, SAE_PK_M_LEN);
	}

	memcpy(hash, fullhash + P_BYTES_SEC, P_BYTES_OUT);
}


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
	// Generate random starting point
	read_random(sig, P_BYTES_OUT);

	// Note that in our workshop code P_BYTES_OUT represents the actual password
	// bits which EXCLUDES the leading zeros.
}


void reduce(int table_idx, u8 sig[P_BYTES_OUT], u8 modifier[16])
{
	memset(modifier, 0, 16);

	// Simplify by assuming we have at most 2^16 tables
	modifier[0] = table_idx / 256;
	modifier[1] = table_idx % 256;

	// After this there is always enough space left
	memcpy(modifier + 2, sig, P_BYTES_OUT);
}


int hash_to_distinguished_point(int table_idx, size_t hash_len, char *ssid, size_t ssid_len, struct wpabuf *pub, u8 sig[P_BYTES_OUT])
{
	u8 modifier[16] = {0};
	unsigned long long i;
	int j;

	// Reduce and apply hash until we have a distinguished point
	for (i = 0; i < T_MAX; ++i)
	{
		// Reduce previous signature output to new input
		reduce(table_idx, sig, modifier);

		// Calculate the PKHASH
		pkhash(hash_len, ssid, ssid_len, modifier, pub, sig);
		//hex_dump(sig, P_BYTES_OUT, "sig: ");

		// Check if we have a distinguished point
		for (j = 0; j < P_BYTES_D; ++j)
			if (sig[j] != 0)
				break;
		if (j == P_BYTES_D)
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
	int j;

	memcpy(sig, chain->start_sig, P_BYTES_OUT);

	// Reduce and apply hash until we have a distinguished point
	for (i = 0; i < T_MAX; ++i)
	{
		// Reduce previous signature output to new input
		reduce(table_idx, sig, modifier);

		// Calculate the PKHASH
		pkhash(hash_len, ssid, ssid_len, modifier, pub, sig);
		//hex_dump(sig, P_BYTES_OUT, "sig: ");

		if (memcmp(sig, to_find, P_BYTES_OUT) == 0)
			return 1;

		// Check if we have a distinguished point
		for (j = 0; j < P_BYTES_D; ++j)
			if (sig[j] != 0)
				break;
		if (j == P_BYTES_D)
			break;
	}

	return 0;
}


struct chain_t * create_chain(int table_idx, size_t hash_len, char *ssid, size_t ssid_len, struct wpabuf *pub)
{
	struct chain_t *chain = malloc(sizeof(struct chain_t));
	u8 sig[P_BYTES_OUT];

	// Generate random starting point
	rand_sig(chain->start_sig);
	//hex_dump(chain->start_sig, P_BYTES_OUT, "Starting point: ");

	// Reduce and apply hash until we have a distinguished point
	memcpy(sig, chain->start_sig, P_BYTES_OUT);
	int len = hash_to_distinguished_point(table_idx, hash_len, ssid, ssid_len, pub, sig);
	if (len >= 0) {
		memcpy(chain->end_sig, sig, P_BYTES_OUT);
		//hex_dump(chain->end_sig, P_BYTES_OUT, "End point     : ");
		chain->len = len;
		return chain;
	} else {
		free(chain);
		return NULL;
	}
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

				if (other->len > chain->len)
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
		if (chain == NULL)
			stats.num_null_chains += 1;
	}

	return table;
}


int lookup_in_table(struct table_t *table, size_t hash_len, char *ssid, size_t ssid_len, struct wpabuf *pub, u8 sig[P_BYTES_OUT])
{
	u8 sig_dp[P_BYTES_OUT];

	// Hash sig until we get a distinguished point
	memcpy(sig_dp, sig, P_BYTES_OUT);
	if (hash_to_distinguished_point(table->index, hash_len, ssid, ssid_len, pub, sig_dp) < 0) {
		stats.num_lookup_dp_fails += 1;
		return 0;
	}

	// Look up the distinguished point --- TODO XXX implement using binary search
	//hex_dump(sig, P_BYTES_OUT, "Looking for  : ");
	//hex_dump(sig_dp, P_BYTES_OUT, "Distinguished: ");
	stats.num_lookups++;
	for (int i = 0; i < P_M; ++i)
	{
		if (table->chains[i] == NULL)
			continue;

		//hex_dump(table->chains[i]->start_sig, P_BYTES_OUT, "Starting sig    : ");
		//hex_dump(table->chains[i]->end_sig, P_BYTES_OUT, "Distingished sig: ");
		if (memcmp(table->chains[i]->end_sig, sig_dp, P_BYTES_OUT) != 0)
			continue;

		if (find_in_chain(table->index, hash_len, ssid, ssid_len, pub, table->chains[i], sig)) {
			stats.num_found += 1;
			return 1;
		} else
			stats.num_false_alarms += 1;
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
		//printf("Duplicate chains: %lu\n", stats.num_duplicates);
		printf("Created table %d/%d. Duplicate chains over all tables: %lu\n", i, P_R, stats.num_duplicates);
	}

	printf("Table done at: %ld\n", time(NULL));
	printf("Duplicate chains: %lu\n", stats.num_duplicates);

	printf("---\n");

#ifdef TEST_LOOKUP
	/** Make it so we will look up known elements */
	srand(init_rand);
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
		reduce(0, sig, modifier);

		// Calculate the PKHASH
		pkhash(hash_len, ssid, ssid_len, modifier, pub, sig);
#endif

		printf("Trying to look up random sig (%lu/%lu)\n", i, stats.num_tests);
		lookup(tables, hash_len, ssid, ssid_len, pub, sig);

		if (i % 100 == 0) {
			printf("Tests done at: %ld\n", time(NULL));
			printf("---\n");
			printf("Out of %lu lookups:\n", i);
			printf("- Passwords found : %lu\n", stats.num_found);
			printf("- False alarms    : %lu\n", stats.num_false_alarms);
			printf("- Tot pkhash calls: %lu\n", stats.num_pkhash_calls);
			printf("- Tot null chains : %lu\n", stats.num_null_chains);
			printf("- DP hash fails during lookup : %lu\n", stats.num_lookup_dp_fails);
			printf("- Total no. of table lookups  : %lu\n", stats.num_lookups);
			printf("---\n");
		}
	}

	printf("Tests done at: %ld\n", time(NULL));
	printf("---\n");
	printf("Out of %lu lookups:\n", stats.num_tests);
	printf("- Passwords found : %lu\n", stats.num_found);
	printf("- False alarms    : %lu\n", stats.num_false_alarms);
	printf("- Tot pkhash calls: %lu\n", stats.num_pkhash_calls);
	printf("- Tot null chains : %lu\n", stats.num_null_chains);
	printf("- DP hash fails during lookup : %lu\n", stats.num_lookup_dp_fails);
	printf("- Total no. of table lookups  : %lu\n", stats.num_lookups);
	printf("---\n");

	ret = 0;
fail:
	os_free(der);
	wpabuf_free(pub);
	crypto_ec_key_deinit(key);

	os_program_deinit();

	return ret;
}

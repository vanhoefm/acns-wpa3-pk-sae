# Rainbow code simulation

## Background

This repository contains code to estimate the success probability of rainbow tables against WPA3's SAE-PK.
The code can also be used to measure the number of chain collisions during the table generation, and to
measure the number of table accesses and hash computations during password lookups. The parameters of the
tables, and the length/security of the passwords being targeted, can be controlled using `define`'s in the
source code.

Please note that the tables are not saved to disk. The memory storage requirement of the tables is not
optimized. In other words, this code is used to analyze properties of (small-scale) rainbow tables, but
not to perform attacks in practice.

Some parts of the code are based on [hostap](https://w1.fi/cvs.html).


## Usage

You can build the tool using:

	cd hostapd
	cp defconfig .config
	make sae_pk_tmto sae_pk_rainbow

You can now experiment with rainbow table by executing:

	./sae_pk_rainbow example_key.der 5 testnetwork

To experiment with time-memory trade-off attacks using distinguished points
only, you can execute:

	./sae_pk_tmto example_key.der 5 testnetwork

The first argument is the private key that will be used, the second argument
represent the security level of the SAE-PK password, and the third argument
denotes the SSID to use in the experiment. The tool will generate the table
and by default will try to look up 400 random passwords in the table.


## Parameters

The start of `sae_pk_tmto.c` and `sae_pk_rainbow.c` contain parameters to control the generation
properties of the tables:

```
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
```

#!/usr/bin/env python3
import argparse, struct, base64
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# ----------------------- Verhoeff algo ----------------------------

# Based on https://github.com/openweave/openweave-core/blob/e3c8ca3d416a2e1687d6f5b7cec0b7d0bf1e590e/src/lib/support/verhoeff/Verhoeff.py#L24
CharSet_Base32 = "abcdefghijklmnopqrstuvwxyz234567"
PermTable_Base32 = [ 7,   2,  1, 30, 16, 20, 27, 11, 31,  6,  8, 13, 29,  5, 10, 21, 22,  3, 24,  0, 23, 25, 12,  9, 28, 14,  4, 15, 17, 18, 19, 26 ]

def DihedralMultiply(x, y, n):
	n2 = n * 2

	x = x % n2
	y = y % n2

	if (x < n):
		if (y < n):
			return (x + y) % n
		else:
			return ((x + (y - n)) % n) + n
	else:
		if (y < n):
			return ((n + (x - n) - y) % n) + n
		else:
			return (n + (x - n) - (y - n)) % n

def DihedralInvert(val, n):
	if (val > 0 and val < n):
		return n - val
	else:
		return val

def Permute(val, permTable, iterCount):
	val = val % len(permTable);
	if (iterCount == 0):
		return val
	else:
		return Permute(permTable[val], permTable, iterCount - 1)

def _ComputeCheckChar(str, strLen, polygonSize=16):
	c = 0
	for i in range(1, strLen+1):
		ch = str[strLen - i]
		val = CharSet_Base32.index(ch)
		p = Permute(val, PermTable_Base32, i)
		c = DihedralMultiply(c, p, polygonSize)
	c = DihedralInvert(c, polygonSize)
	return CharSet_Base32[c]

def ComputeCheckChar32(string, charSet=CharSet_Base32):
	return _ComputeCheckChar(string, len(string), polygonSize=16)

def VerifyCheckChar32(string):
	expectedCheckCh = _ComputeCheckChar(string, len(string)-1)
	return str[-1] == expectedCheckCh  


# ------------------------- SAE-PK PW GEN ------------------------------

def key_to_hashlen(priv_key):
	if priv_key.key_size == 256:
		return 32
	elif priv_key.key_size == 384:
		return 48
	elif priv_key.key_size == 521:
		return 64
	else:
		raise Exception(f"Unsupported ECC curve {priv_key.curve}")


def get_pubkey_compressed(priv_key_data):
	priv_key = serialization.load_der_private_key(priv_key_data, None)
	hash_len = key_to_hashlen(priv_key)
	pub_key = priv_key.public_key()

	pubkey_rfc5480_uncompressed = pub_key.public_bytes(serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)

	compressedKey = pub_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
	idx = pubkey_rfc5480_uncompressed.index(compressedKey[1:])
	pubkey_rfc5480 = pubkey_rfc5480_uncompressed[:idx - 3] + struct.pack(">B", len(compressedKey) + 1) + \
				pubkey_rfc5480_uncompressed[idx-2:idx - 1] + compressedKey
	pubkey_rfc5480 = pubkey_rfc5480[:1] + struct.pack(">B", len(pubkey_rfc5480) - 2) + pubkey_rfc5480[2:]

	return pubkey_rfc5480, hash_len


def sae_hash(data, hash_len):
	if hash_len == 	32:
		digest = hashes.Hash(hashes.SHA256())
	elif hash_len == 48:
		digest = hashes.Hash(hashes.SHA384())
	elif hash_len == 64:
		digest = hashes.Hash(hashes.SHA512())
	digest.update(data)
	return digest.finalize()


def binstr2pw(pw_base_bin, num_chargroups=3):
	temp = pw_base_bin[:20 * num_chargroups - 5]
	temp = temp + "0" * (8 - (len(temp) % 8))
	temp = int(temp, 2).to_bytes((len(temp) + 7) // 8)
	pw = base64.b32encode(temp).decode('utf-8').lower().strip('=')
	pw = pw[:-1] + ComputeCheckChar32(pw[:-1])
	pw = "-".join(pw[i:i+4] for i in range(0, len(pw), 4))
	return pw

def main(args):
	expected = 256**args.sec

	priv_key_data = open(args.der_private_key, "rb").read()
	pubkey_rfc5480, hash_len = get_pubkey_compressed(priv_key_data)
	print("Compressed Pub Key:", pubkey_rfc5480.hex())

	for modifier in range(2**128):
		data = args.ssid.encode("utf-8") + int.to_bytes(modifier, 16) + pubkey_rfc5480
		hash_result = sae_hash(data, hash_len)
		if hash_result[0] == 0 and hash_result[1] == 0:
			print(f"Progress: {modifier / expected * 100:.4f}%")
			if hash_result[:args.sec] == b"\x00" * args.sec:
				print(f"Found a valid hash in {modifier + 1} iterations: {hash_result.hex()}")
				break

	# Skip 8*Sec bits and add Sec_1b as the every 20th bit starting with one
	sec_1b = 1 if args.sec == 3 else 0
	pw_base_bin = bin(int.from_bytes(hash_result[args.sec:])).strip("0b")
	pw_base_bin = "0" * ( len(hash_result[args.sec:]) * 8 - len(pw_base_bin) - 1 ) + pw_base_bin
	pw_base_bin = str(sec_1b) + str(sec_1b).join(pw_base_bin[i:i+19] for i in range(0, len(pw_base_bin), 19))

	pw = binstr2pw(pw_base_bin, 3)
	b64key = base64.b64encode(priv_key_data).decode('utf-8')
	print(f"sae_password={pw}|pk={modifier.to_bytes(16).hex()}:{b64key}")

	print("# Longer passwords can be used for improved security at the cost of usability:")
	for i in range(4,10):
		print("#", binstr2pw(pw_base_bin, i))

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Generate WPA3 SAE-PK passwords in Python')
	parser.add_argument('der_private_key')
	parser.add_argument('sec', type=int)
	parser.add_argument('ssid')
	args = parser.parse_args()

	if not args.sec in [3, 5]:
		print(f"Argument sec must equal either 3 or 5 (was {args.sec})")
		quit(1)

	main(args)


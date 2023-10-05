This repository was copied from [https://github.com/wifithings/wpa3tools](https://github.com/wifithings/wpa3tools).

# Background

This repo has python scripts to generate WPA3 SAE-PK passwords.

# Usage

First generate a private key:

```
openssl ecparam -name prime256v1 -genkey -noout -out example_key.der -outform der
```

Now derive the password from it:

```
./python_pkgen.py example_key.der 3 wpa3net
```

Replace `test1` with the SSID of the WPA2 network. The 3 represents passwords whose first 3 bytes are zero. You can also use the value 5 for stornger passwords, but this script is low to generate such stronger passwords.


# Configuring the Password in Hostapd

The output can be directly used in Hostapd. For instance, the output will be:

```
Found a valid hash in 1745720 iterations: 00000015945be5d28095283a07269bdaecf5c095901c68939c5c4e7866100892
Base binary string:  000101011001010001011011111001011101001010000000100101010010100000111010000001110010011010011011110110101110110011110101110000001001010110010000000111000110100010010011100111000101110001001110011110000110011000010000000010001001001
Base binary string: 1000101011001010001011101111100101110100110100000001001010101010100000111010000010111001001101001101111101101011101100111110101110000001001011011001000000011100101101000100100111001111000101110001001111001111000011001100100100000000100010011001
sae_password=rlfc-56lu-2ajd|pk=000000000000000000000000001aa337:MHcCAQEEIHgNg5jMTEjtfbKvGQbmLy/fsKBbb82+jqCXTfZTt9OLoAoGCCqGSM49AwEHoUQDQgAE4lnQIAr+ExiVadrg6KrAFkW/BTOSrnL2DuMmZikiRfWG46qY1gMdaxFaxXzYZcPWeOtDnSUSMSdIafAB0y9HKg==
# Longer passwords can be used for improved security at the cost of usability:
# rlfc-56lu-2ajk-va5d
# rlfc-56lu-2ajk-va5a-xe25
# rlfc-56lu-2ajk-va5a-xe2n-625s
# rlfc-56lu-2ajk-va5a-xe2n-625t-5oap
# rlfc-56lu-2ajk-va5a-xe2n-625t-5oas-3eax
# rlfc-56lu-2ajk-va5a-xe2n-625t-5oas-3ea4-wrek
```

The `sae_password` field can be directly copied to the Hostapd config file.

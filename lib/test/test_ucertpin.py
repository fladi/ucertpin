"""
Certificate pinning for MicroPython.

MIT license; Copyright (c) 2021 Martin Komon
"""

# pylint: disable = wrong-import-position, wrong-import-order

# check platform
import sys
if sys.implementation.name != 'micropython':
    print('ucertpin works only with MicroPython, tests must be run also on MicroPython. '
        'Please upload the tests to a MicroPython device and run the tests there.')
    sys.exit(1)

# check Internet connectivity
import usocket
internet_connection = False
try:
    if any([usocket.getaddrinfo(addr, 80) for addr in ['google.com', 'github.com']]):
        internet_connection = True
except OSError:
    pass
if not internet_connection:
    print('Please provide working Internet connection before running the tests!')
    sys.exit(1)

import urequests
import gc
from ucertpin import *

address_list = [
    'https://github.com/',
    'https://www.ssllabs.com',
    'https://www.micropython.org',
    'https://www.google.com',
    'https://portal.azure.com',
]

def run_tests():
    gc.collect()
    for addr in address_list:
        if not addr.startswith('https'):
            print(f'addresses must start with "https"! Skipping address {addr}')
        try:
            response = urequests.get(addr)
        except NotImplementedError:
            print(f'Redirects are not supported by requests package. Skipping address {addr}')
            gc.collect()
            continue
        server_cert = response.raw.getpeercert(True)
        try:
            parse_x509(server_cert)
            print(f'Success parsing certificate for {addr}')
        except:
            print(f'Error parsing certificate for {addr}')
            raise

        del response
        del server_cert
        gc.collect()

        try:
            get_pubkey_hash_from_url(addr)
            print(f'Success getting pubkey hash for {addr}')
        except:
            print(f'Error getting pubkey hash for {addr}')
            raise

        gc.collect()

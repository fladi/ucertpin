"""
Certificate pinning for MicroPython.

MIT license; Copyright (c) 2021 Martin Komon

Usage:
    import ucertpin
    import urequests
    my_url = 'https://www.ssllabs.com/'
    my_pubkey_hash = 'fc4b5fd6816f75a7c81fc8eaa9499d6a299bd803397166e8c4cf9280b801d62c'

    response = urequests.get(my_url)
    remote_hash = ucertpin.get_pubkey_hash_from_der(response.raw.getpeercert(True))
    if remote_hash != my_pubkey_hash:
        print('The public key of the remote server is not as expected!')
        ...
"""

import uasn1

def parse_x509(x509_der):
    """
    Parses x509 certificate in DER encoding and returns a tuple with the following fields:
    - version number (int)
    - serial number (int)
    - signature algorithm (tuple (OID, argument))
    - issuer_name (dictionary of "OID: value" items)
    - validity period (tuple not_valid_before, not_valid_after)
    - subject_name (dictionary of "OID: value" items)
    - subject public key (tuple type (OID), public key)
    - raw_optional_fields (list of optional fields not parsed any further )
    - certificate signature algorithm (tuple (OID, argument))
    - certificate signature (bytes)

    Returned public key may require further parsing, depending on its type. Namely RSA key remains
    in DER encoding and includes an exponent; EC keys do not require further parsing.

    Validity period data has the format returned by DER-parsing module uasn1, i.e. YYMMDDhhmmssZ
    """
    # pylint: disable=too-many-locals, too-many-statements
    d = uasn1.Decoder()
    d.start(x509_der)
    d.enter()
    _, cert = d.read()
    _, cert_sig_alg = d.read()
    _, cert_sig = d.read()

    d.start(cert)
    _, raw_version_number = d.read()
    _, serial_number = d.read()
    _, raw_sig_alg = d.read()
    _, raw_issuer_name = d.read()
    _, raw_validity_period = d.read()
    _, raw_subject_name = d.read()
    _, raw_subject_pubkey_info = d.read()
    raw_optional_fields = []
    while not d.eof():
        _, field = d.read()
        raw_optional_fields.append(field)

    d.start(raw_version_number)
    _, version_number = d.read()

    d.start(raw_sig_alg)
    _, sig_alg_id = d.read()
    if d.eof():
        sig_alg_arg = None
    else:
        _, sig_alg_arg = d.read()

    d.start(raw_issuer_name)
    issuer_name = {}
    while not d.eof():
        d.enter()
        d.enter()
        _, oid = d.read()
        _, val = d.read()
        d.leave()
        d.leave()
        issuer_name[oid] = val

    d.start(raw_validity_period)
    _, t1 = d.read()
    _, t2 = d.read()
    validity_period = (t1, t2)

    d.start(raw_subject_name)
    subject_name = {}
    while not d.eof():
        d.enter()
        d.enter()
        _, oid = d.read()
        _, value = d.read()
        d.leave()
        d.leave()
        subject_name[oid] = value

    d.start(raw_subject_pubkey_info)
    _, raw_subject_pubkey_type = d.read()
    _, raw_subject_pubkey = d.read()

    d.start(raw_subject_pubkey_type)
    _, subject_pubkey_type = d.read()

    d.start(cert_sig_alg)
    _, cert_sig_alg_oid = d.read()
    if d.eof():
        cert_sig_alg_params = None
    else:
        _, cert_sig_alg_params = d.read()

    return (
        version_number,
        serial_number,
        (sig_alg_id, sig_alg_arg),
        issuer_name,
        validity_period,
        subject_name,
        (subject_pubkey_type, raw_subject_pubkey),
        raw_optional_fields,
        (cert_sig_alg_oid, cert_sig_alg_params),
        cert_sig
    )

def get_pubkey(x509_der) -> bytes:
    """Extract public key from a x509 certificate."""
    return parse_x509(x509_der)[6][1]


def get_pubkey_hash_from_der(x509_der) -> str:
    """Extract public key from a x509 certificate and return its SHA256 hash."""

    import hashlib
    import ubinascii

    h = hashlib.sha256()
    h.update(get_pubkey(x509_der))
    return ubinascii.hexlify(h.digest())


def get_pubkey_hash_from_url(url) -> str:
    """
    Obtain an SSL certificate from server given its URL, extract the public key from it
    and return its SHA256 hash.
    """
    try:
        import urequests
    except ImportError:
        import requests as urequests

    try:
        response = urequests.get(url)
    except OSError:
        print('Cannot get SSL certificate from server. Check internet connection and try again.')

    try:
        return get_pubkey_hash_from_der(response.raw.getpeercert(True))
    except:
        print("Other error when processing received SSL certificate.")
        return ''

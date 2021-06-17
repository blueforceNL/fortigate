#!/usr/bin/python3

# This program tries to reveal the model and serial number from Fortigate devices.
# A TCP connection is made to port 541 with TLS in server mode.

import socket
import ssl
import sys
import os
from OpenSSL import crypto


def cert_gen(certfile, keyfile):
    # generate key:
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().CN = 'localhost'
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    with open(certfile, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(keyfile, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))


if len(sys.argv) != 2:
    exit("Use %s <ip|fqdn>" % sys.argv[0])

target_addr = sys.argv[1]
target_port = 541  # Fortigate management
timeout = 3  # seconds

# Generate key and certificate files
pid = os.getpid()
cert_file = "/tmp/fortigate-%i.crt" % pid
key_file = "/tmp/fortigate-%i.key" % pid
cert_gen(cert_file, key_file)

# Prepare TLS Context
context = ssl.SSLContext(ssl.PROTOCOL_TLS)

# Fortigate acts as TLS client.
# Certificate contains model and serial number.
context.verify_mode = ssl.CERT_REQUIRED

# Accept weak security settings. Certificate key is too weak.
context.set_ciphers('ALL:@SECLEVEL=0')

# Local (dummy) server certificate and key
context.load_cert_chain(cert_file, key_file)

# Fortinet CA certificates to validate incoming client certificate.
# Downloaded from the Fortinet demo appliance.
context.load_verify_locations(cadata="""
-----BEGIN CERTIFICATE-----
MIID1TCCAr2gAwIBAgIJANr2NrRD1KWLMA0GCSqGSIb3DQEBCwUAMIGgMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2YWxl
MREwDwYDVQQKEwhGb3J0aW5ldDEeMBwGA1UECxMVQ2VydGlmaWNhdGUgQXV0aG9y
aXR5MRAwDgYDVQQDEwdzdXBwb3J0MSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0QGZv
cnRpbmV0LmNvbTAeFw0xNTA3MTYyMjM0MzlaFw0zODAxMTkyMjM0MzlaMIGgMQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2
YWxlMREwDwYDVQQKEwhGb3J0aW5ldDEeMBwGA1UECxMVQ2VydGlmaWNhdGUgQXV0
aG9yaXR5MRAwDgYDVQQDEwdzdXBwb3J0MSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0
QGZvcnRpbmV0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANQ7
UXPQNRISyMNOWUFI0TvBsKbVD4MhKYt4v+vDRJ3GZoKa7gQfoJ+r4M14xWzTNN26
NrJtUutYSUmDmX/m5rbo24JjtGdx1FzKL6+3cDKHUDV8wZCI0DQZLamhgbNJ7fv0
VergsuJXxp8urzFJA25pbqxH9X6u1lOs4NqCM6CTHvVp+IqmZGucVmFQTMh9fiE0
L20IFY0K5wc/C3XP1Pa0CzXLu6smjtr0prwXisGSiTkxg0+HTSO24tv0q5ABPgfz
OWKpX9b6gaMt17r3hSi5GhKElbCDGLtMbdKcldboxNBQZ5nxPRNFS26Lde5duB8j
oc6Rwdgv9dsxSS17HWMCAwEAAaMQMA4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAhxf7jexnSrTNshppXpiMmlK5C9HxuQQZQT/dq0FkmN/7cp6rtgl3
6WUfBU95ia0q9GJnaxbSWpXO4jq4wT5vlGCIEaiajJLJx1BFRu7dMUZnkmoyIvKT
893YUGlAZeGME/WXVBaAHsj4wIhYIOMvUm7VB3wUK9SjZtn0qGEz+OjxmWjnJ2+c
k67pZbRLl8gOuRB6OkFIiNp8slO08g4lXIYquHIltC7RCadNQPz3qfYvW4npIW49
04JH4CUAtzvbRdDs4MCvszKuPOICvm6pnqin1AIqJ+4cMwPrVVyBN5NsIhohAUjS
ELtlWJR1qQ7HT5Q9tVLCr/qOnEHEkoy4hw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIKLDCCBhSgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBpTELMAkGA1UEBhMCVVMx
EzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1bm55dmFsZTERMA8GA1UE
ChMIRm9ydGluZXQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEVMBMG
A1UEAxMMZm9ydGluZXQtY2EyMSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0QGZvcnRp
bmV0LmNvbTAgFw0xNjA2MDYyMDI3MzlaGA8yMDU2MDUyNzIwMjczOVowgaUxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTdW5ueXZh
bGUxETAPBgNVBAoTCEZvcnRpbmV0MR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBBdXRo
b3JpdHkxFTATBgNVBAMTDGZvcnRpbmV0LWNhMjEjMCEGCSqGSIb3DQEJARYUc3Vw
cG9ydEBmb3J0aW5ldC5jb20wggQiMA0GCSqGSIb3DQEBAQUAA4IEDwAwggQKAoIE
AQC9YkiEs7iwMQVeJuZyV5hYi8RGwE5N8X8I8jLo1BI/r/HD/RbbtmPBkyWVgPpa
RQnAgnupxy06qJcWNrinZBxZyqKJrqke2RIBstV3lfoevSP7pmjF2raDZqL7EaDG
kvRzaLyei5pifzcBzpoY8TpBk6upDD2pjkU60MqgWY/0Eo7SsiTKAukWvEqK3mL0
K05+UNcEYzboWi0tIMBgXIYgIDDmYvOqUbDnPFYRTZQ6eltSFWrU+TvR4wEhBcwg
DxlFQHY02Ee9UxEav4Ej02KzdjDKq3ZKMHaczGLiam4N/5TwtLG5+7il2TZ309Uf
4Tjr5aWvEKMvHNTI4/hLDd+DsUs43qf0yD8HQ4kzpkyEEzdfXxPjbt6UNX7Dlz2T
DQXvcqESs27kRxcEQ3gmVeL3cyDC4R4G3DhyBQQxNi22rROOX5DRMNC0TIrLslld
RBMZfDbSUOrLZobfuOE4bMDHGz7pzJWxqkfBI/GoO9G4ZMFxC5JYr2/3lzod5K4P
lGRyWUJ9vax2JIeF5DM/UgfBdqhZetTXLKnKCOxT85cseAeYT335vlHNo/YVnYg5
LFfCpqAJMJYjFz9EG6oOBXeT34GHwtXOxpaib1uYqM6REzhiqSRLvwYdlQtXM7Tn
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
x+nkkKoLQHPUczTwYRxQUQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIH6zCCA9OgAwIBAgICIAEwDQYJKoZIhvcNAQELBQAwgaUxCzAJBgNVBAYTAlVT
MRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTdW5ueXZhbGUxETAPBgNV
BAoTCEZvcnRpbmV0MR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxFTAT
BgNVBAMTDGZvcnRpbmV0LWNhMjEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmb3J0
aW5ldC5jb20wIBcNMTYwNjA2MjA0ODMzWhgPMjA1NjA1MjcyMDQ4MzNaMIGrMQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2
YWxlMREwDwYDVQQKEwhGb3J0aW5ldDEeMBwGA1UECxMVQ2VydGlmaWNhdGUgQXV0
aG9yaXR5MRswGQYDVQQDExJmb3J0aW5ldC1zdWJjYTIwMDExIzAhBgkqhkiG9w0B
CQEWFHN1cHBvcnRAZm9ydGluZXQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA3uzK/FLbKVH9xgTgDlyqXEs3RalzOKeFgewal656b9D4BD966MoS
951b1Q/L5cByMzuT5ClpFqlP0KpUBgXS8PQ88juxYNc9SQsKzunM1j91sUJFupDV
LiBCH0PrGGCRKTcNElgnCOvVtYWMmf6JUx6VJGyhVfpgltOebPXgs+WTCNDPe6ip
/z17qR4l402LFtt2df3tlgJMlLQxUo37x9UYW8Edw5OtXZZ04Nwsh7FJjmp/nHSm
4owISiSlq9ECnXRvZzAqpCKhxZCj+5O5ibGutUHSpyALhp5akhPFxrWsqqeBFFW/
CtkqRIuCJWpQ0bdcUoZzZFrpalv0mg2SpQIDAQABo4IBGTCCARUwHQYDVR0OBBYE
FJgrJTwwyiwrVufb/Fkzs9w9W2rXMIHSBgNVHSMEgcowgceAFKMxr6NI7qHiX7Hy
/db7QUhQGzp1oYGrpIGoMIGlMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZv
cm5pYTESMBAGA1UEBxMJU3Vubnl2YWxlMREwDwYDVQQKEwhGb3J0aW5ldDEeMBwG
A1UECxMVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRUwEwYDVQQDEwxmb3J0aW5ldC1j
YTIxIzAhBgkqhkiG9w0BCQEWFHN1cHBvcnRAZm9ydGluZXQuY29tggEAMA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IEAQAv
9F8uzJw3xVXxDuXbOpL3r0oo01fSfXEuinFBYXcZzk3iF2PGEDX7s7CE7PQ1ne7l
/LXaVDR/G7RB2m6HYDIZhAV4h3Ru+YfgL/cpMgjkbl1L+BqI9wMjyK+FqHwnGW3B
8iPzBd6WWJOBLZ/x/4XLknkg9C+h2Skj9LMMIsCXIyoR7OP4Pbsotv5jU6qM11C1
2QCkC4rHjgL7jHrlY40sSL/nqv9og18EGL9VwQRPKNgLPjPNnUGkPtr6DCWCD/Mv
rvd6qCvVG/t4mgZ8/DTZ2eluVW98sETOJ7kakdk1WKGSSp4UE2e1Kpwgt1GD3OGD
IYRQlezdUj3CbqKbE0Cm/ESKsOybVvTrMeK9HBJQ6Ma4DJwxp/OF+3F5ROasHSAV
9Y+y53aD87FqLmzntd24ovxjaAOo/AJy5+MFnTCEeRnjng7hdOPdknglA7PHHqjn
H/olodK4xEBMSgFB+xP3Ca26Ld9kuDsLkuVWpjCr5+40BozrX4oPvL1GC0kSYU/D
1mDuo23sL40yFkrUQxK9mABwaqkxETpLsKmFm4YFOtvrAlx1GOZKT2QAuY3jYdZi
KcH5D7bE85GZ4eaehtJ2fTQSP/hRjEZFnC6j7wIbqazKehswR3yo4+DWSNk9yaFe
mGxuQwaTr3wdw1z2dWfL/pU/iMdh7CVUe9GdJfPOQACgVVJ1jr80rhxE0Av0Ku3P
YASqqP7f3NpQK6AlveKndEYVxYePHXEOuYlTNb272DxWC70PwF6vVjZlohCxd/4/
K9pMZr9FLLWM4oKC8ciKaykiyVfqJZdaleamqUkKmRllUxmajzW9nr99HHPMjiHN
K1oWackR9q+0ZKAoOx5Zq2Yc1jehfZGTSbXFhFdqnOdQMBYoxnL/TNHs4QJXe2Va
n6DCziL4BKOb4LskmWE7Flw5A6JDqSW8zhQMbiSl6yutrXzcP5RxQ7hLsaoO/7oC
IvBOnSAMu2uKhbttrekwFpogB4oC+YIWlFGY0emuwYJAAVu6QQL8c6OOw8zyJouX
3wjAmsxbT9X+PtYpekEbeBBPoQPH4qFmKyJJJ0a65iTq/Kmeeq2ywwAxdZK5foZG
0D4oNOhFbO9Mg+Noc0lDpSjEkS9rckHJj4tIjotq7OBZ7ZGYzsnadQI1/GZbebK/
cFMMH85UHc/46k/0lBWjDjFyDIliPRRCnV3Y+TFO3c8GN/SRofspod5vrAQdnMjF
iZHJUTLZ1iRMo7wWMXtJ04R+h8dtz5FbSgC8gDKmvNOU1ucMFpfLtzcgoKD8eZTq
IN/gJdRSPLzwVuu9AHZOAwo9BzfrtbzLVK20sXN7xKBOdXUwbzaX9axZE2TQOjDB
rLhbvd2nZoW0QmqqVpTr
-----END CERTIFICATE-----
""")

try:
    # Make connection with TLS in server mode
    sock = socket.create_connection((target_addr, target_port), timeout)
    ssock = context.wrap_socket(sock, server_side=True)

    common_name = ssock.getpeercert()['subject'][5][0][1]
    not_after = ssock.getpeercert()['notAfter']

    ssock.close()

    # Remove certificate and key files
    os.remove(cert_file)
    os.remove(key_file)

    if len(common_name) and len(not_after):
        print("Fortigate model and s/n: %s, device certificate expiry: %s"
              % (common_name, not_after))
    else:
        exit("No information from device.")

except Exception as e:
    exit(e)

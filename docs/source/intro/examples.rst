Examples
========

Expired Certificates
^^^^^^^^^^^^^^^^^^^^

A simple use for Cryptonice is to check for expiring or expired certificates. This can either be accomplished
by using default parameters or specifically (and only) scanning for the website certificate.

**Using Cryptonice to check for expired certificates at expired.badssl.com**:
::
  cryptonice f5.com --scans tls --tls_parameters certificate_info

Results:
::
  RESULTS
  -------------------------------------
  Hostname:                         expired.badssl.com

  CERTIFICATE
  Common Name:                      *.badssl.com
  Public Key Algorithm:             RSA
  Public Key Size:                  2048
  Signature Algorithm:              sha256

  Certificate is trusted:           False (Mozilla not trusted)
  Hostname Validation:              OK - Certificate matches server hostname
  Extended Validation:              False
  Certificate is in date:           False
  Days until expiry:                -1923
  Valid From:                       2015-04-09 00:00:00
  Valid Until:                      2015-04-12 23:59:59

  OCSP Response:                    Unsuccessful
  Must Staple Extension:            False

  Subject Alternative Names:
            *.badssl.com
            badssl.com

  RECOMMENDATIONS
  -------------------------------------
  CRITICAL - Cert Expiry Certificate has expired!

  Scans complete
  -------------------------------------
  Total run time: 0:00:19.095761

  Outputting data to ./expired.badssl.com.json

We can see from the output, above, that the certificate for expired.badssl.com has expired 1923 days ago
and that the certificate is also, therefore, not trusted by the Mozilla root store.


Weak Protocols and Ciphers
^^^^^^^^^^^^^^^^^^^^^^^^^^

Legacy protocols are either deliberately made available in order to accept connections
from old browsers or, all too often, they are forgotten about and not removed despite known vulnerabilities.

Cryptonice will detect which ciphersuites are available over which protocol and display warnings should
legacy ciphers be found.

**Using Cryptonice to check for weak protocols and ciphers on rc4-md5.badssl.com**:
::
  cryptonice f5.com --scans tls

Results:
::
  RESULTS
  -------------------------------------
  Hostname:                         rc4-md5.badssl.com

  Selected Cipher Suite:            RC4-MD5
  Selected TLS Version:             TLS_1_1

  Supported protocols:
  TLS 1.2:                          Yes
  TLS 1.1:                          Yes
  TLS 1.0:                          Yes


  RECOMMENDATIONS
  -------------------------------------
  HIGH - TLSv1.0 Major browsers are disabling TLS 1.0 imminently. Carefully monitor if clients still use this protocol.
  HIGH - RC4 The RC4 symmetric cipher is considered weak and should not be used
  HIGH - MD5 The MD5 message authentication code is considered weak and should not be used
  HIGH - TLSv1.1 Major browsers are disabling this TLS 1.1 immenently. Carefully monitor if clients still use this protocol.

  Scans complete
  -------------------------------------
  Total run time: 0:00:26.915821

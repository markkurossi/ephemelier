# TLS 1.3

[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.txt)

## Mandatory-to-Implement Cipher Suites (9.1.)

The RFC 8446 defines the mandatory-to-implement cipher suites as
follows:

```txt
   A TLS-compliant application MUST implement the TLS_AES_128_GCM_SHA256
   [GCM] cipher suite and SHOULD implement the TLS_AES_256_GCM_SHA384
   [GCM] and TLS_CHACHA20_POLY1305_SHA256 [RFC8439] cipher suites (see
   Appendix B.4).

   A TLS-compliant application MUST support digital signatures with
   rsa_pkcs1_sha256 (for certificates), rsa_pss_rsae_sha256 (for
   CertificateVerify and certificates), and ecdsa_secp256r1_sha256.  A
   TLS-compliant application MUST support key exchange with secp256r1
   (NIST P-256) and SHOULD support key exchange with X25519 [RFC7748].
```

This implementation will implement:

 - `TLS_AES_128_GCM_SHA256`
 - `ecdsa_secp256r1_sha256`
 - `secp256r1`

### ClientHello Default Proposals `key_share`

 - OpenSSL  : X25519MLKEM768[1216] x25519[32]
 - chrome   : X25519MLKEM768[1216] x25519[32]
 - Go 1.25.0: X25519MLKEM768[1216] x25519[32]

```shell
apps/openssl s_client -connect localhost:8443 -debug -msg
```

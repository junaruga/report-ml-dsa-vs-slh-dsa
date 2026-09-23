# report-ml-dsa-vs-slh-dsa

ML-DSA supports seed and mu params. SLH-DSA don't support the params.

```
$ ruby -I /home/jaruga/var/git/ruby/openssl/lib ml_dsa_vs_slh_dsa.rb
Ruby OpenSSL 4.0.2: OpenSSL 4.1.0-dev
ML-DSA:  #<OpenSSL::PKey::PKey:0x00007f51c3d04cd0 type_name=ML-DSA-44 provider=default>
SLH-DSA: #<OpenSSL::PKey::PKey:0x00007f51c3d04ca8 type_name=SLH-DSA-SHA2-128f provider=default>
ML-DSA  get_param('seed'): 32 bytes
SLH-DSA get_param('seed'): raised OpenSSL::PKey::PKeyError - unrecognized OSSL_PARAM key: seed
ML-DSA  sign with mu=1: sig size=2420
SLH-DSA sign with mu=1: OpenSSL::PKey::PKeyError - EVP_PKEY_CTX_ctrl_str(ctx, "mu", "1"): command not supported ([action:2, state:4] name=mu, value=1)
```

ML-DSA supports `EVP_PKEY_sign_message_update` (streaming signing). SLH-DSA doesn't support it.

```
$ ./compile.sh

$ ./streaming_sign
OpenSSL version: OpenSSL 4.1.0-dev

Dispatch table entries in OpenSSL providers:
  ML-DSA:  SIGN_MESSAGE_UPDATE registered (ml_dsa_sig.c:480)
  SLH-DSA: SIGN_MESSAGE_UPDATE NOT registered (slh_dsa_sig.c:352-377)
  Neither registers DIGEST_SIGN_UPDATE.

=== ML-DSA-44 ===
  One-shot  (EVP_DigestSign):             OK (sig=2420 bytes)
  Old API (EVP_DigestSignUpdate): FAIL (EVP_DigestSignUpdate) - digest_sign_update is NULL
  OpenSSL error: error:030000ED:digital envelope routines::provider signature not supported
  New API (EVP_PKEY_sign_message_update): OK (sig=2420 bytes)

=== SLH-DSA-SHA2-128f ===
  One-shot  (EVP_DigestSign):             OK (sig=17088 bytes)
  Old API (EVP_DigestSignUpdate): FAIL (EVP_DigestSignUpdate) - digest_sign_update is NULL
  OpenSSL error: error:030000ED:digital envelope routines::provider signature not supported
  New API (EVP_PKEY_sign_message_update): FAIL (EVP_PKEY_sign_message_update) - sign_message_update is NULL
  OpenSSL error: error:030000ED:digital envelope routines::provider signature not supported
```

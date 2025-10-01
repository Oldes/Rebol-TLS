Rebol [
    title: "TLS Protocol Constants and Enumerations"
    file:  %tls-constants.reb
    license: MIT ;= SPDX-License-Identifier
]


*Protocol-type: enum [
    CHANGE_CIPHER_SPEC: 20
    ALERT:              21
    HANDSHAKE:          22 ;0x16
    APPLICATION:        23
] 'TLS-protocol-type

*Protocol-version: enum [
    SSLv3:  0#0300
    TLS1.0: 0#0301
    TLS1.1: 0#0302
    TLS1.2: 0#0303
    TLS1.3: 0#0304
;   DTLS1.0: 0#FEFF
;   DTLS1.2: 0#FEFD
;   DTLS1.3: 0#FEFC
] 'TLS-Protocol-version

*Handshake: enum [
    HELLO_REQUEST:        0
    CLIENT_HELLO:         1
    SERVER_HELLO:         2
    NEW_SESSION_TICKET:   4 ;; post-handshake in 1.3
    ENCRYPTED_EXTENSIONS: 8
    CERTIFICATE:         11
    SERVER_KEY_EXCHANGE: 12
    CERTIFICATE_REQUEST: 13
    SERVER_HELLO_DONE:   14
    CERTIFICATE_VERIFY:  15
    CLIENT_KEY_EXCHANGE: 16 ;0x10
    FINISHED:            20
    KEY_UPDATE:          24
] 'TLS-Handshake-type

*Cipher-suite: enum [
;   TLS 1.3 cipher suites (AEAD+hash only)
    TLS_AES-128-GCM_SHA256:                        0#1301
    TLS_AES-256-GCM_SHA384:                        0#1302
    TLS_CHACHA20-POLY1305_SHA256:                  0#1303
    TLS_AES-128-CCM_SHA256:                        0#1304  ; optional
    TLS_AES-128-CCM_8_SHA256:                      0#1305  ; optional

;   Elyptic curves:
    TLS_ECDHE_RSA_WITH_CHACHA20-POLY1305_SHA256:   0#CCA8
    TLS_ECDHE_ECDSA_WITH_CHACHA20-POLY1305_SHA256: 0#CCA9
    TLS_ECDHE_RSA_WITH_AES-256-CBC_SHA384:         0#C028
    TLS_ECDHE_RSA_WITH_AES-128-GCM_SHA256:         0#C02F
    TLS_ECDHE_RSA_WITH_AES-256-GCM_SHA384:         0#C030
    TLS_ECDHE_ECDSA_WITH_AES-128-GCM_SHA256:       0#C02B
    TLS_ECDHE_ECDSA_WITH_AES-256-GCM_SHA384:       0#C02C
    TLS_ECDHE_RSA_WITH_AES-128-CBC_SHA256:         0#C027
    TLS_ECDHE_ECDSA_WITH_AES-256-CBC_SHA384:       0#C024
    TLS_ECDHE_ECDSA_WITH_AES-128-CBC_SHA256:       0#C023
    TLS_ECDHE_RSA_WITH_AES-128-CBC_SHA:            0#C013
    TLS_ECDHE_ECDSA_WITH_AES-128-CBC_SHA:          0#C009
    TLS_ECDHE_RSA_WITH_AES-256-CBC_SHA:            0#C014
    TLS_ECDHE_ECDSA_WITH_AES-256-CBC_SHA:          0#C00A

    TLS_ECDH_ECDSA_WITH_AES-256-GCM_SHA384:        0#C02E ; ECDH does not support Perfect Forward Secrecy (PFS)

    TLS_DHE_RSA_WITH_AES-128-CCM:                  0#C09E
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM:              0#C0AD

;   The following CipherSuite definitions require that the server provide
;   an RSA certificate that can be used for key exchange.  The server may
;   request any signature-capable certificate in the certificate request
;   message.

    TLS_RSA_WITH_AES-128-GCM_SHA256:               0#009C

    TLS_RSA_WITH_NULL_MD5:                         0#0001
    TLS_RSA_WITH_NULL_SHA:                         0#0002
    TLS_RSA_WITH_NULL_SHA256:                      0#003B
    TLS_RSA_WITH_RC4-128_MD5:                      0#0004
    TLS_RSA_WITH_RC4-128_SHA:                      0#0005
    TLS_RSA_WITH_3DES-EDE-CBC_SHA:                 0#000A
    TLS_RSA_WITH_AES-128-CBC_SHA:                  0#002F
    TLS_RSA_WITH_AES-256-CBC_SHA:                  0#0035
    TLS_RSA_WITH_AES-128-CBC_SHA256:               0#003C
    TLS_RSA_WITH_AES-256-CBC_SHA256:               0#003D

;   The following cipher suite definitions are used for server-
;   authenticated (and optionally client-authenticated) Diffie-Hellman.
;   DH denotes cipher suites in which the server's certificate contains
;   the Diffie-Hellman parameters signed by the certificate authority
;   (CA).  DHE denotes ephemeral Diffie-Hellman, where the Diffie-Hellman
;   parameters are signed by a signature-capable certificate, which has
;   been signed by the CA.  The signing algorithm used by the server is
;   specified after the DHE component of the CipherSuite name.  The
;   server can request any signature-capable certificate from the client
;   for client authentication, or it may request a Diffie-Hellman
;   certificate.  Any Diffie-Hellman certificate provided by the client
;   must use the parameters (group and generator) described by the
;   server.

    TLS_DH_DSS_WITH_3DES-EDE-CBC_SHA:    0#0D
    TLS_DH_RSA_WITH_3DES-EDE-CBC_SHA:    0#10
    TLS_DHE_DSS_WITH_3DES-EDE-CBC_SHA:   0#13
    TLS_DHE_RSA_WITH_3DES-EDE-CBC_SHA:   0#16
    TLS_DH_DSS_WITH_AES-128-CBC_SHA:     0#30
    TLS_DH_RSA_WITH_AES-128-CBC_SHA:     0#31
    TLS_DHE_DSS_WITH_AES-128-CBC_SHA:    0#32
    TLS_DHE_RSA_WITH_AES-128-CBC_SHA:    0#33
    TLS_DH_DSS_WITH_AES-256-CBC_SHA:     0#36
    TLS_DH_RSA_WITH_AES-256-CBC_SHA:     0#37
    TLS_DHE_DSS_WITH_AES-256-CBC_SHA:    0#38
    TLS_DHE_RSA_WITH_AES-256-CBC_SHA:    0#39
    TLS_DH_DSS_WITH_AES-128-CBC_SHA256:  0#3E
    TLS_DH_RSA_WITH_AES-128-CBC_SHA256:  0#3F
    TLS_DHE_DSS_WITH_AES-128-CBC_SHA256: 0#40
    TLS_DHE_RSA_WITH_AES-128-CBC_SHA256: 0#67
    TLS_DH_DSS_WITH_AES-256-CBC_SHA256:  0#68
    TLS_DH_RSA_WITH_AES-256-CBC_SHA256:  0#69
    TLS_DHE_DSS_WITH_AES-256-CBC_SHA256: 0#6A
    TLS_DHE_RSA_WITH_AES-256-CBC_SHA256: 0#6B

;   The following cipher suites are used for completely anonymous
;   Diffie-Hellman communications in which neither party is
;   authenticated.  Note that this mode is vulnerable to man-in-the-
;   middle attacks.  Using this mode therefore is of limited use: These
;   cipher suites MUST NOT be used by TLS 1.2 implementations unless the
;   application layer has specifically requested to allow anonymous key
;   exchange.  (Anonymous key exchange may sometimes be acceptable, for
;   example, to support opportunistic encryption when no set-up for
;   authentication is in place, or when TLS is used as part of more
;   complex security protocols that have other means to ensure
;   authentication.)

    TLS_DH_anon_WITH_RC4-128_MD5:        0#18
    TLS_DH_anon_WITH_3DES-EDE-CBC_SHA:   0#1B
    TLS_DH_anon_WITH_AES-128-CBC_SHA:    0#34
    TLS_DH_anon_WITH_AES-256-CBC_SHA:    0#3A
    TLS_DH_anon_WITH_AES-128-CBC_SHA256: 0#6C
    TLS_DH_anon_WITH_AES-256-CBC_SHA256: 0#6D

    PSUEDO-CIPHER-SUITE: 0#FF ;; renegotiation SCSV supported

] 'TLS-Cipher-suite

*EllipticCurves: enum [
    secp192r1:  0#13
    secp224k1:  0#14
    secp224r1:  0#15
    secp256k1:  0#16
    secp256r1:  0#17
    secp384r1:  0#18
    secp521r1:  0#19
    bp256r1:    0#1A
    bp384r1:    0#1B
    bp512r1:    0#1C
    curve25519: 0#1D ;? or x25519
    curve448:   0#1E ;? or x448
] 'EllipticCurves

*HashAlgorithm: enum [
    none:       0
    md5:        1
    sha1:       2
    sha224:     3
    sha256:     4
    sha384:     5
    sha512:     6
    md5_sha1: 255
] 'TLSHashAlgorithm

*SignatureAlgorithm: enum [
    rsa_pkcs1_sha1:         0#0401
    rsa_pkcs1_sha224:       0#0501
    rsa_pkcs1_sha256:       0#0601
    rsa_pkcs1_sha384:       0#0701
    rsa_pkcs1_sha512:       0#0801
    rsa_pss_rsae_sha256:    0#0804
    rsa_pss_rsae_sha384:    0#0805
    rsa_pss_rsae_sha512:    0#0806
    rsa_pss_pss_sha256:     0#0807
    rsa_pss_pss_sha384:     0#0808
    rsa_pss_pss_sha512:     0#0809
    ecdsa_secp256r1_sha256: 0#0403
    ecdsa_secp384r1_sha384: 0#0503
    ecdsa_secp521r1_sha512: 0#0603
    ed25519:                0#080A
    ed448:                  0#080B
] 'TLSSignatureAlgorithm

*ClientCertificateType: enum [
    rsa_sign:                  1
    dss_sign:                  2
    rsa_fixed_dh:              3
    dss_fixed_dh:              4
    rsa_ephemeral_dh_RESERVED: 5
    dss_ephemeral_dh_RESERVED: 6
    fortezza_dms_RESERVED:     20
    ecdsa_sign:                64
    rsa_fixed_ecdh:            65
    ecdsa_fixed_ecdh:          66
] 'TLSClientCertificateType

*Alert-level: enum [
    WARNING: 1
    FATAL:   2
] 'TLS-Alert-level

*Alert: enum [
    Close_notify:             0
    Unexpected_message:      10
    Bad_record_MAC:          20
    Decryption_failed:       21
    Record_overflow:         22
    Decompression_failure:   30
    Handshake_failure:       40
    No_certificate:          41
    Bad_certificate:         42
    Unsupported_certificate: 43
    Certificate_revoked:     44
    Certificate_expired:     45
    Certificate_unknown:     46
    Illegal_parameter:       47
    Unknown_CA:              48
    Access_denied:           49
    Decode_error:            50
    Decrypt_error:           51
    Export_restriction:      60
    Protocol_version:        70
    Insufficient_security:   71
    Internal_error:          80
    User_cancelled:          90
    No_renegotiation:       100
    Unsupported_extension:  110
] 'TLS-Alert

*TLS-Extension: enum [
    server_name:                             0 ; RFC 6066
    max_fragment_length:                     1 ; RFC 6066
    status_request:                          5 ; RFC 6066
    supported_groups:                       10 ; RFC 8422, 7919
    supported_point_formats:                11
    signature_algorithms:                   13 ; RFC 8446
    use_srtp:                               14 ; RFC 5764
    heartbeat:                              15 ; RFC 6520
    application_layer_protocol_negotiation: 16 ; RFC 7301
    signed_certificate_timestamp:           18 ; RFC 6962
    client_certificate_type:                19 ; RFC 7250
    server_certificate_type:                20 ; RFC 7250
    padding:                                21 ; RFC 7685
    encrypt_then_MAC:                       22
    extended_master_secret:                 23
    compress_certificate:                   27 ; https://datatracker.ietf.org/doc/html/rfc8879
    session_ticket:                         35
    pre_shared_key:                         41 ; RFC 8446
    early_data:                             42 ; RFC 8446
    supported_versions:                     43 ; RFC 8446
    cookie:                                 44 ; RFC 8446
    psk_key_exchange_modes:                 45 ; RFC 8446
    certificate_authorities:                47 ; RFC 8446
    oid_filters:                            48 ; RFC 8446
    post_handshake_auth:                    49 ; RFC 8446
    signature_algorithms_cert:              50 ; RFC 8446
    key_share:                              51 ; RFC 8446
    encrypted_client_hello:             0#FE0D ; https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-08
    renegotiation_info:                 0#FF01 ;@@ https://tools.ietf.org/html/rfc5746
] 'TLS-Extension

*TLS-CertCompression: enum [
    zlib:   1
    brotli: 2
] 'TLS-CertCompression

hash-len: make map! [sha384: 48 sha256: 32]

signature-hash-methods: make map! [
    ecdsa_secp256r1_sha256:            sha256
    ecdsa_secp384r1_sha384:            sha384
    ecdsa_secp521r1_sha512:            sha512
    ecdsa_brainpoolP256r1tls13_sha256: sha256
    ecdsa_brainpoolP384r1tls13_sha384: sha384
    ecdsa_brainpoolP512r1tls13_sha512: sha512
    rsa_pss_pss_sha256:                sha256
    rsa_pss_pss_sha384:                sha384
    rsa_pss_pss_sha512:                sha512
    rsa_pss_rsae_sha256:               sha256
    rsa_pss_rsae_sha384:               sha384
    rsa_pss_rsae_sha512:               sha512
    rsa_pkcs1_sha256:                  sha256
    rsa_pkcs1_sha384:                  sha384
    rsa_pkcs1_sha512:                  sha512
]

HRR-magic: #{CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C} ;= HelloRetryRequest server random magic value
server-certificate-verify-context: rejoin [
    #{2020202020202020202020202020202020202020202020202020202020202020
      2020202020202020202020202020202020202020202020202020202020202020}
    "TLS 1.3, server CertificateVerify^@"
]

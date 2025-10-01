Rebol [
    title: "TLS Cipher Suite Configuration"
    file:  %tls-cipher-suites.reb
    license: MIT ;= SPDX-License-Identifier
]

;-- list of supported suites as a single binary
; This list is sent to the server when negotiating which one to use.  Hence
; it should be ORDERED BY CLIENT PREFERENCE (more preferred suites first).
; Use https://ciphersuite.info for security info!

TLS13-cipher-suites: make binary! 60
TLS12-cipher-suites: make binary! 60
if find system/catalog/ciphers 'chacha20-poly1305 [
    append TLS13-cipher-suites #{
        1303 ;TLS_CHACHA20_POLY1305_SHA256
    }
    append TLS12-cipher-suites #{
        CCA9 ;TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ;= recommended
        CCA8 ;TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   ;= secure
    }
]
if find system/catalog/ciphers 'aes-128-gcm [
    append TLS13-cipher-suites #{
        1302 ;TLS_AES_256_GCM_SHA384
        1301 ;TLS_AES_128_GCM_SHA256
        1304 ;TLS_AES_128_CCM_SHA256
    }
    append TLS12-cipher-suites #{
        C02B ;TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ;= recommended
        C02C ;TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ;= recommended
;       C030 ;TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   ;= secure
        C02F ;TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   ;= secure
        009C ;TLS_RSA_WITH_AES_128_GCM_SHA256         ;= weak
    }
]
if find system/catalog/ciphers 'aes-128-cbc [
    append TLS12-cipher-suites #{
        ;- CBC mode is considered to be weak, but still used!
        C028 ;TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        C024 ;TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        C027 ;TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        C023 ;TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        C014 ;TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        C013 ;TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        C00A ;TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        C009 ;TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
;       006A ;TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
        006B ;TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        0067 ;TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        003D ;TLS_RSA_WITH_AES_256_CBC_SHA256
        003C ;TLS_RSA_WITH_AES_128_CBC_SHA256
        0035 ;TLS_RSA_WITH_AES_256_CBC_SHA
        002F ;TLS_RSA_WITH_AES_128_CBC_SHA
;       0038 ;TLS_DHE_DSS_WITH_AES_256_CBC_SHA
;       0032 ;TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        0039 ;TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        0033 ;TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    }
]

;- RC4 is prohibited by https://tools.ietf.org/html/rfc7465 for insufficient security
;if native? :rc4 [
;   append TLS12-cipher-suites #{
;       0004 ;TLS_RSA_WITH_RC4_128_MD5 
;       0005 ;TLS_RSA_WITH_RC4_128_SHA
;   }
;]

suported-cipher-suites-binary: rejoin [
#{;- OpenSSL client ciphers
    1302 ; TLS_AES_256_GCM_SHA384
;    1303 ; TLS_CHACHA20_POLY1305_SHA256
    1301 ; TLS_AES_128_GCM_SHA256
    c02c ; TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    c030 ; TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    009f ; TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    cca9 ; TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    cca8 ; TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    ccaa ; TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    c02b ; TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    c02f ; TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    009e ; TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    c024 ; TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    c028 ; TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    006b ; TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    c023 ; TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    c027 ; TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    0067 ; TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    c00a ; TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    c014 ; TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0039 ; TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    c009 ; TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    c013 ; TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0033 ; TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    009d ; TLS_RSA_WITH_AES_256_GCM_SHA384
    009c ; TLS_RSA_WITH_AES_128_GCM_SHA256
    003d ; TLS_RSA_WITH_AES_256_CBC_SHA256
    003c ; TLS_RSA_WITH_AES_128_CBC_SHA256
    0035 ; TLS_RSA_WITH_AES_256_CBC_SHA
    002f ; TLS_RSA_WITH_AES_128_CBC_SHA
}
;   TLS13-cipher-suites
;   TLS12-cipher-suites
    #{00ff}  ;; TLS_EMPTY_RENEGOTIATION_INFO_SCSV (psuedo-cipher-suite)
]
;suported-cipher-suites-binary: TLS12-cipher-suites
suported-cipher-suites: decode-list *Cipher-suite :suported-cipher-suites-binary _

supported-signature-algorithms: #{

    0403 ; ecdsa_secp256r1_sha256
    0503 ; ecdsa_secp384r1_sha384
    0603 ; ecdsa_secp521r1_sha512
    0807 ; ed25519
;   0808 ; ed448
    0401 ; rsa_pkcs1_sha256
    0501 ; rsa_pkcs1_sha384
    0601 ; rsa_pkcs1_sha512

;   0703 ; curve25519 (EdDSA algorithm)
;   0602 ; SHA512 DSA
;   0502 ; SHA384 DSA

    0402 ; SHA256 DSA

;   0301 ; SHA224 RSA
;   0302 ; SHA224 DSA
;   0303 ; SHA224 ECDSA
;   0201 ; rsa_pkcs1_sha1
;   0202 ; SHA1 DSA
;   0203 ; ecdsa_sha1
}
supported-signature-algorithms: #{
0403 ; ecdsa_secp256r1_sha256
0503 ; ecdsa_secp384r1_sha384
0603 ; ecdsa_secp521r1_sha512
0807 ; ed25519
;0808 ; ed448
;081a ; ecdsa_brainpoolP256r1tls13_sha256
;081b ; ecdsa_brainpoolP384r1tls13_sha384
;081c ; ecdsa_brainpoolP512r1tls13_sha512
;0809 ; rsa_pss_pss_sha256
;080a ; rsa_pss_pss_sha384
;080b ; rsa_pss_pss_sha512

;- TLS1.3 required signature algorithm for handshake messages (CertificateVerify)
0804 ; rsa_pss_rsae_sha256
0805 ; rsa_pss_rsae_sha384
0806 ; rsa_pss_rsae_sha512

;- primarily used for certificate signatures
0401 ; rsa_pkcs1_sha256
0501 ; rsa_pkcs1_sha384
0601 ; rsa_pkcs1_sha512
;0303 ; SHA224 ECDSA
;0301 ; SHA224 RSA
;0302 ; SHA224 DSA
;0402 ; SHA256 DSA
;0502 ; SHA384 DSA
;0602 ; SHA512 DSA
}

supported-elliptic-curves: make binary! 22
supported-groups: make block! 12
foreach curve system/schemes/tls/spec/supported-groups [
    ;; Collect only curves, which are available.
    if find system/catalog/elliptic-curves curve [
        append supported-groups curve
        binary/write tail supported-elliptic-curves [UI16BE :*EllipticCurves/:curve]
    ]
]


supported-versions: #{
    04    ; length
    0304  ; TLS1.3
    0303  ; TLS1.2
;   0302  ; TLS1.1
;   0301  ; TLS1.0
}

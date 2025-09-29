Rebol [
    Title: "TLS Context Object Definition"
    SPDX-License-Identifier: Apache-2.0
    File: %tls-init.reb
]

TLS-context: context [
    in:  binary 16104 ;input binary codec
    out: binary 16104 ;output binary codec
    bin: binary 64    ;temporary binary

    tcp-port:
    tls-port:
    encrypt-port:
    decrypt-port: 
    sha256-port:   ;used for progressive checksum computations
    sha384-port:   ;used for progressive checksum computations with SHA384 cipher modes
    sha-port:      ;one of the above
    md5-port: none ;used for progressive checksum computations (in TLSv1.0)


    legacy-version: 0#0303
    version:  none ; TLS version (currently just TLSv1.2)
    TLS13?:   none
    handshake?: true

    port-data:   make binary! 32000 ;this holds received decrypted application data
    rest:        make binary! 8 ;packet may not be fully processed, this value is used to keep temporary leftover
    reading?:       false  ;if client is reading or writing data
    server?:        false  ;always FALSE now as we have just a client
    protocol:       none   ;current protocol state. One of: [HANDSHAKE APPLICATION ALERT]
    state:         'lookup ;current state in context of the protocol
    state-prev:     none   ;previous state

    error:                 ;used to hold Rebol error object (for reports to above layer)
    critical-error:        ;used to signalize error state
    cipher-suite:   none
    cipher-spec-set: 0     ;stores state of cipher spec exchange (0 = none, 1 = client, 2 = both)
    ecdh-group:     none   ;EllipticCurve group used to create key_share

    ;- values defined inside TLS-init-cipher-suite:
    key-method:            ; one of: [RSA DH_DSS DH_RSA DHE_DSS DHE_RSA]
    hash-type:             ; one of: [MD5 SHA1 SHA256 SHA384]
    crypt-method:   none
    is-aead?:       false  ; crypt-method with "Authenticated Encryption with Additional Data" (not yet supported!)
    aad-length:
    tag-length:
       IV-size:            ; The amount of data needed to be generated for the initialization vector.
       IV-size-dynamic:
      mac-size:            ; Size of message authentication code
    crypt-size:            ; The number of bytes from the key_block that are used for generating the write keys.
    block-size:  0         ; The amount of data a block cipher enciphers in one chunk; a block
                           ; cipher running in CBC mode can only encrypt an even multiple of
                           ; its block size.

    locale-hs-IV:
    locale-ap-IV:
    locale-hs-key:
    locale-ap-key:
    locale-mac:
    locale-random:
    locale-hs-secret:
    locale-ap-secret:

    remote-hs-IV:
    remote-ap-IV:
    remote-hs-key:
    remote-ap-key:
    remote-mac:
    remote-random:
    remote-hs-secret:
    remote-ap-secret:
    
    finished-hash:
    handshake-secret:
    verify-data:
    client-verify-data: ;; hash which sends client to server after handshake

    dh-key:
    aead: none ; used now for chacha20/poly1305 combo

    session-id: none        ; https://hpbn.co/transport-layer-security-tls/#tls-session-resumption
    server-certs: copy []
    extensions:   copy []
    context-messages: []

    seq-read:  0 ; sequence counters
    seq-write: 0

    
    pre-secret:
    master-secret:
    certificate:
    pub-key:
    pub-exp:
    key-data:
    hello-retry-request: 
        none
]

derived-secrets: make map! []
zero-keys:       make map! []
empty-hash:      make map! []




TLS-init-context: func [
    ;; Resets and initializes the TLS context object for a new connection, including sequence numbers and server certificates.
    ctx [object!]
][
    ctx/seq-read: ctx/seq-write: 0
    ctx/protocol: ctx/state: ctx/state-prev: none
    ctx/cipher-spec-set: 0 ;no encryption yet
    clear ctx/server-certs
]

TLS-init-cipher-suite: func [
    ;; Sets up the context fields required for a particular cipher suite, including cryptographic and hash parameters.
    ctx [object!]
    /local suite key-method cipher
][
    cipher: ctx/cipher-suite
    suite: *Cipher-suite/name :cipher
    unless suite [
        log-error ["Unknown cipher suite:" enbase suite 16]
        return false
    ]
    unless find suported-cipher-suites suite [
        unless ctx/server? [log-error ["Server requests" suite "cipher suite!"]]
        return false
    ]

    log-info ["Init TLS Cipher-suite:^[[35m" suite "^[[22m" skip to binary! cipher 6]

    parse form suite [
        opt "TLS_"
        opt [copy key-method to "_WITH_" 6 skip (ctx/key-method: to word! key-method)] ; used up to TLS1.2
        copy cipher [
              "CHACHA20-POLY1305" (ctx/crypt-size: 32 ctx/IV-size: 12 ctx/block-size: 16  )
            | "AES-256-GCM"  (ctx/crypt-size: 32 ctx/IV-size: 4 ctx/IV-size-dynamic: 8 ctx/tag-length: ctx/block-size: 16 ctx/aad-length: 13 )
            | "AES-128-GCM"  (ctx/crypt-size: 16 ctx/IV-size: 4 ctx/IV-size-dynamic: 8 ctx/tag-length: ctx/block-size: 16 ctx/aad-length: 13 )
            | "AES-128-CBC"  (ctx/crypt-size: 16 ctx/IV-size: 16 ctx/block-size: 16  ) ; more common than AES-256-CBC
            | "AES-256-CBC"  (ctx/crypt-size: 32 ctx/IV-size: 16 ctx/block-size: 16  )
            ;| "3DES-EDE-CBC" (ctx/crypt-size: 24 ctx/IV-size: 8  ctx/block-size: 8   )
            | "RC4-128"      (ctx/crypt-size: 16 ctx/IV-size: 0  ctx/block-size: none)
            | "NULL"         (ctx/crypt-size: 0  ctx/IV-size: 0  ctx/block-size: none)
        ] #"_" [
              "SHA384" end (ctx/hash-type: 'SHA384 ctx/mac-size: 48)
            | "SHA256" end (ctx/hash-type: 'SHA256 ctx/mac-size: 32)
            | "SHA"    end (ctx/hash-type: 'SHA1   ctx/mac-size: 20)
            | "SHA512" end (ctx/hash-type: 'SHA512 ctx/mac-size: 64)
            | "MD5"    end (ctx/hash-type: 'MD5    ctx/mac-size: 16)
            | "NULL"   end (ctx/hash-type: none    ctx/mac-size: 0 )
            ;NOTE: in RFC mac-size is named mac_length and there is also mac_key_length, which has same value
        ]
        (
            ctx/crypt-method: to word! cipher
            ctx/is-aead?: to logic! find [AES-128-GCM AES-256-GCM CHACHA20-POLY1305] ctx/crypt-method
            ctx/sha-port: open join checksum:// ctx/hash-type

            log-more [
                "Key:^[[1m" ctx/key-method
                "^[[22mcrypt:^[[1m" ctx/crypt-method
                "^[[22msize:^[[1m" ctx/crypt-size
                "^[[22mIV:^[[1m" ctx/IV-size 
            ]
        )
    ]
]
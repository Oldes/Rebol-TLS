Rebol [
    title: "TLS v1.2 Client Functions"
    file:  %tls12-client.reb
    license: MIT ;= SPDX-License-Identifier
]

decode-server-key-exchange: function [
    ctx     [object!]
    message [binary!]
][
    assert-prev-state ctx [CERTIFICATE SERVER_HELLO]
    msg: binary message
    log-more ["R[" ctx/seq-read "] Using key method:^[[1m" ctx/key-method]
    switch ctx/key-method [
        ECDHE_RSA
        ECDHE_ECDSA [
            ;? msg/buffer
            try/with [
                binary/read msg [
                    ECCurveType: UI8  
                    ECCurve:     UI16     ; IANA CURVE NUMBER
                    pub_key:     UI8BYTES 
                    message-len: INDEXz
                ]
            ][
                log-error "Error reading elyptic curve"
                return 'User_cancelled
            ]
            if any [
                3 <> ECCurveType
                none? curve: *EllipticCurves/name ECCurve
                ;4 <> first pub_key
                
            ][
                log-error ["Unsupported ECurve type:" ECCurveType ECCurve ]
                cause-TLS-error critical-error: 'User_cancelled
            ]
            log-more ["R[" ctx/seq-read "] Elyptic curve type:" ECCurve "=>" curve]
            log-more ["R[" ctx/seq-read "] Elyptic curve data:" mold pub_key]
        ]
        DHE_DSS
        DHE_RSA [
            ;- has DS params
            binary/read msg [
                dh_p:    UI16BYTES
                dh_g:    UI16BYTES
                pub_key: UI16BYTES
                message-len: INDEXz
            ]
        ]
    ]

    verify-data: rejoin [
        ctx/locale-random
        ctx/remote-random
        copy/part message message-len
    ]
    
    ;-- check signature
    binary/read msg [
        algorithm: UI16
        signature: UI16BYTES
    ]

    unless algorithm: *SignatureAlgorithm/name  algorithm [
        log-error "Unknown signature algorithm!"
        cause-TLS-error 'Decode_error
    ]

    hash-algorithm: signature-hash-methods/:algorithm

    log-more ["R[" ctx/seq-read "] Signature Algorithm:" algorithm "=" enbase *SignatureAlgorithm/:algorithm 16]

    key: ctx/server-certs/1/public-key
    switch key/1 [
        ecPublicKey [
            log-more "Checking signature using RSA_fixed_DH"
            ;@@ TODO: rewrite ecdsa/verify to count the hash automatically like it is in rsa/verify now?
            message-hash: checksum verify-data hash-algorithm
            ; test validity:
            ;? ctx/pub-exp
            ecdsa/verify/curve ctx/pub-key message-hash signature ctx/pub-exp
        ]
        rsaEncryption [
            log-more "Checking signature using RSA"
            rsa-key: apply :rsa-init ctx/server-certs/1/public-key/rsaEncryption
            switch algorithm [
                rsa_pss_rsae_sha256
                rsa_pss_rsae_sha384
                rsa_pss_rsae_sha512 [
                    valid?: rsa/verify/pss/hash rsa-key verify-data signature hash-algorithm
                ]
            ]
        ]
    ]
    unless valid? [
        log-error "Failed to validate signature"
        cause-TLS-error 'Decode_error
    ]

    log-more "Signature valid!"
    unless tail? msg/buffer [
        len: ends - pos
        binary/read msg [extra: BYTES :len]
        log-error ["Extra" len "bytes at the end of message:" ellipsize form extra 40]
        cause-TLS-error 'Decode_error
    ]

    if dh_p [
        dh-key: dh-init dh_g dh_p
        ctx/pre-secret: dh/secret dh-key pub_key
        log-more ["DH common secret:" mold ctx/pre-secret]
        ctx/key-data: dh/public :dh-key
        ; release immediately, don't wait on GC
        release :dh-key dh-key: none
    ]
    if curve [
        ;- elyptic curve init
        ;curve is defined above (sent from server as well as server's public key)
        dh-key: ecdh/init none curve
        ctx/pre-secret: ecdh/secret dh-key pub_key
        log-more ["ECDH common secret:^[[32m" mold  ctx/pre-secret]
        ; resolve the public key to supply it to server
        ctx/key-data: ecdh/public :dh-key
        ; release immediately, don't wait on GC
        release :dh-key dh-key: none
    ]
]

decode-client-key-exchange: function [
    ctx     [object!]
    message [binary!]
][
    assert-prev-state ctx [CLIENT_CERTIFICATE SERVER_HELLO_DONE SERVER_HELLO]
    unless ctx/server? [
        log-error "This message is expected on server!"
        cause-TLS-error 'Decode_error
    ]
    switch ctx/key-method [
        ECDHE_RSA
        ECDHE_ECDSA [
            key-data: binary/read msg 'UI8BYTES
            ctx/pre-secret: ecdh/secret ctx/dh-key key-data 
            log-more ["ECDH common secret:^[[32m" ctx/pre-secret]
        ]
        DHE_DSS
        DHE_RSA [
            ;- has DS params
            key-data: binary/read msg 'UI8BYTES
            ;@@TODO!!!
        ]
        RSA [
            key-data: binary/read msg 'UI16BYTES 
            ;@@TODO!!!
        ]
    ]
    TLS-key-expansion ctx
]


prepare-client-key-exchange: function [
    ctx [object!]
][
    log-debug ["client-key-exchange -> method:" ctx/key-method "key-data:" mold ctx/key-data]

    change-state ctx 'CLIENT_KEY_EXCHANGE
    assert-prev-state ctx [CLIENT_CERTIFICATE SERVER_HELLO_DONE SERVER_HELLO]

    with ctx [
        ;@@TODO: simplify: don't write directly to out!
        binary/write out [
                UI8  22          ; protocol type (22=Handshake)
                UI16 :version    ; protocol version
            pos-record-len:
                UI16 0           ; length of the (following) record data
            pos-record:
                UI8  16          ; protocol message type (16=ClientKeyExchange)
            pos-message:
                UI24 0           ; protocol message length
            pos-key: 
        ]

        switch key-method [
            ECDHE_ECDSA
            ECDHE_RSA [
                log-more ["W[" seq-write "] Using ECDH key-method"]
                key-data-len-bytes: 1
            ]
            RSA [
                log-more ["W[" seq-write "] Using RSA key-method"]

                ; generate pre-secret
                binary/write bin [
                    UI16 :version RANDOM-BYTES 46 ;writes genereted secret (first 2 bytes are version)
                ]
                ; read the temprary random bytes back to store them for client's use
                binary/read bin [pre-secret: BYTES 48]
                binary/init bin 0 ;clears temp bin buffer


                log-more ["W[" seq-write "] pre-secret:" mold pre-secret]

                ;log-debug "encrypting pre-secret:"

                ;?? pre-secret
                ;?? pub-key
                ;?? pub-exp

                rsa-key: rsa-init pub-key pub-exp

                ; supply encrypted pre-secret to server
                key-data: rsa/encrypt rsa-key pre-secret
                key-data-len-bytes: 2
                log-more ["W[" seq-write "] key-data:" mold key-data]
                release :rsa-key ; don't wait on GC and release it immediately
            ]
            DHE_DSS
            DHE_RSA [
                log-more ["W[" seq-write "] Using DH key-method"]
                key-data-len-bytes: 2
            ]
        ]

        ;compute used lengths
        length-message: key-data-len-bytes + length? key-data
        length-record:  4 + length-message

        ;and write them with key data
        binary/write out compose [
            AT :pos-record-len UI16 :length-record
            AT :pos-message    UI24 :length-message
            ; for ECDH only 1 byte is used to store length!
            AT :pos-key (pick [UI8BYTES UI16BYTES] key-data-len-bytes) :key-data
        ]
        TLS-key-expansion ctx
        TLS-update-messages-hash/part ctx (at head out/buffer pos-record) length-record
    ]
]
Rebol [
    title: "TLS Handshake messages and parsing"
    file:  %tls-protocol.reb
    license: 'MIT ;= SPDX-License-Identifier
]

TLS-update-messages-hash: func [
    ;; Updates the running handshake transcript hash with message data for MAC and protocol verification.
    ctx [object! ]    ;; TLS context containing hash ports and methods
    msg [binary! ]    ;; New message fragment to update the hash with
    /part
    len [integer!]    ;; Number of bytes from msg to incorporate
][
    unless ctx/handshake? [exit]
    len: any [len length? msg]
    repend ctx/context-messages [ ctx/state copy/part msg len]
]

get-transcript-hash: function [
    ctx [object!]
    stop-state [word! none!]
][
    sha: open any [
        ctx/sha-port
        ctx/sha-port: open join checksum:// ctx/hash-type
    ]
    foreach [state bin] ctx/context-messages [
        ;probe state ? bin
        write sha bin
        if state = stop-state [break]
    ]
    read sha
]

TLS-parse-handshake-records: function [
    ;; Parses and dispatches one or more handshake messages out of a TLS record buffer.
    ctx  [object!]
][
    bin: binary ctx/port-data 
    while [4 <= length? bin/buffer][
        start: bin/buffer
        binary/read bin [type: UI8 len: UI24]
        if len > length? bin/buffer [
            ;; Not fully received encoded handshake fragment!
            bin/buffer: start ;; reset position to the start of the message
            break             ;; and stop parsing until the message will be complete
        ]
        message: binary/read bin len
        log-debug ["R[" ctx/seq-read "] length:" length? message "type:" type]

        change-state ctx *Handshake/name type

        TLS-update-messages-hash/part ctx start 4 + length? message

        switch/default ctx/state [
            CLIENT_HELLO [ decode-client-hello :ctx :message ]
            SERVER_HELLO [ decode-server-hello :ctx :message ]
            CERTIFICATE  [ decode-certificates :ctx :message ]
            CERTIFICATE_VERIFY [
                decode-certificate-verify :ctx :message
                if ctx/TLS13? [with ctx [
                    finished-key: HKDF-Expand/label hash-type remote-hs-secret #{} mac-size "finished"
                    finished-hash: get-transcript-hash ctx _
                    verify-data: checksum/with finished-hash hash-type finished-key
                    ;; This value must be compared with value sent by server
                    ;prin "CERTIFICATE_VERIFY-> " ?? verify-data ?? context-messages
                ]]
            ]
            FINISHED [
                log-more "Verify handshake data..."
                if ctx/version < 0#0304 [
                    seed: get-transcript-hash ctx _
                    ctx/verify-data: prf :ctx/sha-port/spec/method either ctx/server? ["client finished"]["server finished"] seed ctx/master-secret  12
                ]
                ;log-debug ["R:" message]
                ;log-debug ["L:" ctx/verify-data]
                if ctx/verify-data <> message [
                    return 'Handshake_failure
                ]
                either ctx/server? [
                    switch-to-app-decrypt ctx
                    change-state ctx 'APPLICATION
                ][
                    if ctx/TLS13? [derive-application-traffic-secrets ctx]
                    ctx/reading?: false
                ]
            ]
            ENCRYPTED_EXTENSIONS [
                assert-prev-state ctx [SERVER_HELLO]
                log-more ["R[" ctx/seq-read "] encrypted-extensions:" message]
            ]

            NEW_SESSION_TICKET [
                assert-prev-state ctx [FINISHED APPLICATION]
                ;@@TODO: Implement Session Tickets!
                session-ticket: binary/read message [
                    UI32      ;; Lifetime in seconds
                    UI32      ;; Obfuscation for early-data age
                    UI8BYTES  ;; Per-ticket nonce
                    UI16BYTES ;; Encrypted resumption state
                    UI16BYTES ;; Optional per-ticket extensions
                ]
                log-more ["Session ticket:" mold/flat session-ticket]
                ctx/protocol: 'APPLICATION
                ;; Make NEW_SESSION_TICKET state transparent for the following record
                ctx/state: ctx/state-prev
            ]

            SERVER_KEY_EXCHANGE [ decode-server-key-exchange :ctx :message ]
            CLIENT_KEY_EXCHANGE [ decode-client-key-exchange :ctx :message ]
            CERTIFICATE_REQUEST [ decode-certificate-request :ctx :message ]
            SERVER_HELLO_DONE   [ ctx/reading?: false ]
        ][
            log-error ["Unknown state: " ctx/state "-" type]
            cause-TLS-error 'Unexpected_message
        ]

    ] ;; more messages?
    log-more ["DONE: handshake^[[1m" ctx/state] log-----
    ctx/port-data: truncate bin/buffer ;; remove already processed data
    false ;= no error
]



prepare-change-cipher-spec: function [
    ;; Composes and enqueues the ChangeCipherSpec record for transmission as part of handshake.
    ctx [object!]
][
    change-state ctx 'CHANGE_CIPHER_SPEC
    with ctx [
        binary/write out [
            UI8  20               ;; protocol type (20=ChangeCipherSpec)
            UI16 :legacy-version  ;; protocol version
            UI16 1                ;; length of SSL record data
            UI8  1                ;; CCS protocol type
        ]
    ]
    ctx/cipher-spec-set: 1
]

prepare-wrapped-record: function [
    ;; Encrypts and writes a wrapped TLS record to the output buffer for transmission.
    ctx   [object!]
    plain [binary!]
    type [integer!]
][
    encrypted: wrap-record ctx plain type
    log-more ["W[" ctx/seq-write "] wrapped-record type:" type "bytes:" length? encrypted]
    binary/write ctx/out [
        UI8       23  ; protocol type (23 = Application)
        UI16      :ctx/legacy-version
        UI16BYTES :encrypted
    ] 
]

encrypt-handshake-msg: function [
    ;; Encrypts a handshake message and writes it as a TLS record to the output buffer.
    ctx         [object!]
    unencrypted [binary!]
][
    log-more ["W[" ctx/seq-write "] encrypting-handshake-msg"]
    ;?? unencrypted
    encrypted: encrypt-tls-record/type ctx unencrypted 22
    ;?? encrypted
    ;? ctx/out
    with ctx [
        binary/write out [
            UI8 22                  ; protocol type (22=Handshake)
            UI16 :legacy-version    ; protocol version
            UI16BYTES :encrypted
        ]
    ]
]

decode-cipher-suites: function [
    ;; Decodes a binary list of cipher suite IDs into a block of named suite words.
    bin [binary!]
][
    num: (length? bin) >> 1
    out: make block! num
    bin: binary bin
    loop num [
        if cipher: *Cipher-suite/name binary/read bin 'UI16 [
            append out cipher
            log-debug ["Cipher-suite:" cipher]
        ]
    ]
    out
]


decode-list: function[
    ;; Decodes a length-prefixed binary list of integer values for protocol extensions or cipher details.
    *group [object!]
    bin    [object! binary!]
    len    [word! none!]
][
    either object? bin [
        bytes: binary/read bin len
        if bytes != length? bin/buffer [
            log-error ["Invalid length of the" *group/title* "extension!"]
            cause-TLS-error 'Decode_error
        ]
    ][
        bytes: length? bin
        bin: binary bin
    ]
    num: bytes >> 1
    out: make block! num
    loop num [
        append out *group/name binary/read bin 'UI16
    ]
    trim/all out ;; removes none values
    ;log-debug ["Supported" *group/title* mold out]
    out
]

decode-extensions: function [
    ;; Parses a list of TLS extensions and decodes or dispatches their contents.
    ctx [object!]
    bin [binary!]
][
    bin: binary bin
    out: make map! 4
    while [not empty? bin/buffer][
        binary/read bin [
            ext-type: UI16
            ext-data: UI16BYTES
        ]
        decoded: ext-data
        ;? ext-data
        ext-type: any [*TLS-Extension/name ext-type  ext-type]
        unless empty? ext-data [
            ext-data: binary ext-data
            switch ext-type [
                supported_groups [
                    decoded: decode-list *EllipticCurves ext-data 'UI16
                ]
                supported_versions [
                    ;; https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
                    either ctx/server? [
                        ;; Client sends list of supported TLS versions...
                        num: (binary/read ext-data 'UI8) >> 1
                        decoded: make block! num
                        loop num [
                           append decoded binary/read ext-data 'UI16
                        ]
                    ][
                        ;; Server sends just one TLS version, which wants to use... 
                        either 2 != length? ext-data/buffer [
                            log-error "Invalid length of the supported_versions extension!"
                        ][  decoded: binary/read ext-data 'UI16]
                    ]
                ]
                key_share [
                    bytes: either ctx/server? [
                        binary/read ext-data 'UI16
                    ][  length? ext-data/buffer ]
                    decoded: copy []
                    either bytes == 2 [
                        decoded: binary/read ext-data 'UI16
                    ][
                        while [bytes >= 8][
                            binary/read ext-data [curve: UI16 len: UI16]
                            bytes: bytes - len - 4
                            tmp: binary/read ext-data :len
                            if curve: *EllipticCurves/name curve [
                                repend decoded [curve tmp]
                            ]
                        ]
                    ]
                ]
                server_name [
                    bytes: binary/read ext-data 'UI16
                    case [
                        bytes != length? ext-data/buffer [
                            log-error "Invalid length of the server_name extension!"
                        ]
                        0 != binary/read ext-data 'UI8 [
                            log-error "Unknown server_name type!"
                        ]
                        'else [
                            decoded: to string! binary/read ext-data 'UI16BYTES
                            log-info ["Requested server name:^[[1m" decoded]
                        ]
                    ]
                ]
                signature_algorithms [
                    decoded: decode-list *SignatureScheme ext-data 'UI16 
                ]
                compress_certificate [
                    decoded: decode-list *TLS-CertCompression ext-data 'UI8
                ]
            ]
        ]
        ;? decoded
        out/:ext-type: decoded
        log-more ["Extension:^[[1m" ext-type "^[[2m" mold decoded ]
    ]
    out
]

encode-extension: function [
    ;; Serializes a TLS extension type and its binary value for inclusion in handshake messages.
    ext  [binary!]
    id   [integer!]
    data [binary!]
    /length
][
    either length [
        length: 2 + length? data
        binary/write tail ext [
            UI16      :id
            UI16      :length
            UI16BYTES :data
        ]
    ][
        binary/write tail ext [
            UI16      :id
            UI16BYTES :data
        ]
    ]

]

encode-handshake-record: function [
    ;; Prepares a binary handshake message for transmission, optionally encrypting it in TLS 1.3.
    ctx    [object!]
    record [binary!]
][
    with ctx [
        ;; Count record's hash
        TLS-update-messages-hash ctx record

        if TLS13? [
            record: wrap-record ctx record 0#16
        ]

        ;log-more ["W[" seq-write "] Bytes:" 5 + length? record]

        binary/write out [
            UI8       23        ; protocol type (22=Handshake)
            UI16      :legacy-version
            UI16BYTES :record
        ]
    ]
]
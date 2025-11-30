Rebol [
    title: "TLS Client Implementation"
    file:  %tls-client.reb
    license: 'MIT ;= SPDX-License-Identifier
]

TLS-client-awake: function [
    ;; Handles events relevant to client connections, dispatching logic for reading, writing, connecting, and errors.
    event [event!]
][
    log-debug ["AWAKE Client:^[[1m" event/type]
    TCP-port: event/port
    ctx: TCP-port/extra
    TLS-port: ctx/TLS-port

    if all [
        ctx/protocol = 'APPLICATION
        not TCP-port/data
    ][
        ; reset the data field when interleaving port r/w states
        ;@@ TODO: review this part
        ;log-debug ["reseting data -> " mold TLS-port/data] 
        TLS-port/data: none
    ]

    switch/default event/type [
        lookup [
            open TCP-port
            TLS-init-context ctx
            return false
        ]
        connect [
            if none? ctx [return true] ;- probably closed meanwhile
            return TLS-init-connection ctx
        ]
        wrote [
            ;print ["----- wrote==== " ctx/protocol ctx/state]
            switch ctx/protocol [
                CLOSE-NOTIFY [
                    return true
                ]
                APPLICATION [
                    if ctx/state = 'FINISHED [
                        change-state ctx 'APPLICATION
                        handshake-finished ctx
                        return false
                    ]
                    dispatch-event 'wrote TLS-port
                    return false
                ]
            ]
            ;print "read tcp"
            read TCP-port
            return false
        ]
        read [
            error: try [
                log-debug ["READ TCP" length? TCP-port/data "bytes proto-state:" ctx/protocol]
                ;@@ This part deserves a serious review!                         
                complete?: TLS-read-data ctx TCP-port/data
                ;? port
                if ctx/critical-error [ cause-TLS-error ctx/critical-error ]
                log-debug ["Read complete?" complete? "protocol:" ctx/protocol "state:" ctx/state]
                unless complete? [
                    read TCP-port
                    return false
                ]
                TLS-port/data: ctx/port-data
                binary/init ctx/in none ; resets input buffer
                ;? ctx/protocol
                switch ctx/protocol [
                    APPLICATION [
                        ;- report that we have data to higher layer
                        if all [
                            ctx/state   = 'FINISHED
                            ctx/version == 0#0304 ;= TLS1.3
                        ][
                            ;print "??????????????????????????????????????????"
                            ;? ctx/out
                            ;? ctx/in
                            prepare-finished-message ctx
                            do-TCP-write ctx
                            return false
                        ]

                        dispatch-event 'read TLS-port
                        return true ;= wake up
                    ]
                    HANDSHAKE [
                        switch ctx/state [
                            SERVER_HELLO_DONE [
                                binary/init ctx/out none ;reset output buffer
                                prepare-client-key-exchange ctx
                                prepare-change-cipher-spec ctx
                                prepare-finished-message ctx
                                do-TCP-write ctx
                                return false
                            ]
                            FINISHED [
                                either ctx/server? [
                                    handshake-finished ctx
                                    return true ;= wake up
                                ][
                                    either ctx/TLS13? [
                                        prepare-finished-message ctx
                                        do-TCP-write ctx
                                        return false
                                    ][
                                        change-state ctx ctx/protocol: 'APPLICATION
                                        dispatch-event 'connect ctx/TLS-port
                                        ;print-horizontal-line
                                        return true ;= wake up
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
                ;print "still read TCP-port"
                read TCP-port
                return false
            ]
            ; on error:
            if ctx [ log-error ctx/error: error ]
            dispatch-event 'error TLS-port
            return true
        ]
        close [
            dispatch-event 'close TLS-port
            return true
        ]
        error [
            unless ctx/error [
                ctx/error: case [
                    ctx/state = 'lookup [
                        make error! [
                            code: 500 type: 'access id: 'cannot-open
                            arg1: TCP-port/spec/ref
                        ]
                    ]
                    'else [
                        ;@@ needs better error (unknown reason)
                        ; So far this error is used, when we try to write
                        ; application data larger than 16KiB!
                        make error! [
                            code: 500 type: 'access id: 'protocol
                            arg1: TCP-port/spec/ref
                        ]
                    ]
                ]
            ]
            dispatch-event 'error TLS-port
            return true
        ]
    ][
        close TCP-port
        do make error! rejoin ["Unexpected TLS event: " event/type]
    ]
    false
]

TLS-init-connection: function [
    ;; Starts a new TLS handshake from the client side by sending ClientHello and initializing buffers.
    ctx [object!]
][
    ;; Reset input/output buffers
    binary/init  ctx/out none
    binary/init  ctx/in  none
    prepare-client-hello ctx
    do-TCP-write ctx
    false
]

TLS-read-data: function [
    ;; Reads and parses fragments from the TCP stream into TLS protocol layers,
    ;; handling records for handshake, application, alert, etc.
    ctx       [object!]
    tcp-data  [binary!] 
][
;@@ NOTE: this is not the best solution! Complete stream is collected in the `inp` buffer,
;@@       but we need just parts of it, before it is decrypted! Unfortunatelly the current
;@@       bincode does not allow shrinking of the buffer :-/  NEEDS REWRITE!!!            

    log-debug ["read-data:^[[1m" length? tcp-data "^[[22mbytes previous rest:" length? ctx/rest]
    inp: ctx/in

    binary/write inp ctx/rest  ;; possible leftover from previous packet
    binary/write inp tcp-data  ;; fills input buffer with received data
    clear tcp-data
    clear ctx/rest

    ctx/reading?: true

    while [ctx/reading? and ((available: length? inp/buffer) >= 5)][
        ;log-debug ["Data starts: " copy/part inp/buffer 16]
        binary/read inp [
            start:          INDEX
            type:           UI8
            server-version: UI16
            len:            UI16
        ]
        available: available - 5

        log-debug ["Fragment type: ^[[1m" type "^[[22mver:^[[1m" server-version "/" ctx/version "^[[22mbytes:^[[1m" len "^[[22mbytes"]

        if ctx/legacy-version < server-version [
            ctx/critical-error: 'Internal_error
            return false
        ]
        if available < len [
            ;probe inp/buffer
            log-debug ["Incomplete fragment:^[[22m available^[[1m" available "^[[22mof^[[1m" len "^[[22mbytes"]
            ;?? inp/buffer
            binary/read inp [AT :start] ;resets position
            log-debug ["Data starts: " copy/part inp/buffer 10]

            return false
        ]

        if type != 20 [ ;= unless CHANGE_CIPHER_SPEC
            binary/read inp [data: BYTES :len]
            if ctx/decrypt-port [

                data: decrypt-tls-record ctx data :type
                ;?? data
                if ctx/TLS13? [
                    type: take/last data
                    log-debug ["Inner type:^[[1m" type]
                ]
            ]
            append ctx/port-data data
        ]

        *protocol-type/assert type
        *protocol-version/assert server-version

        protocol: *protocol-type/name type
        version:  *protocol-version/name server-version

        end: start + len + 5 ; header size is 5 bytes

        ;log-debug "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        log-more ["^[[22mR[" ctx/seq-read "] Protocol^[[1m" protocol "^[[22mbytes:^[[1m" len "^[[22mfrom^[[1m" start "^[[22mto^[[1m" end]

        ctx/protocol: protocol

        switch protocol [
            APPLICATION [
                ; first one, as it's the most common
                assert-prev-state ctx [APPLICATION ALERT FINISHED NEW_SESSION_TICKET]
                ;prin "Application " ?? data
                ;@@ TODO: the parent scheme (HTTPS) should be notified here,
                ;@@ that there are already some decrypted data available!   
                ;@@ Now it is awaked only when data are complete :-/        
            ]
            HANDSHAKE [
                ; process the handshake message, set `critical-error` if there is any
                ctx/critical-error: TLS-parse-handshake-records ctx
                ctx/reading?: any [ctx/server? not empty? inp/buffer]
            ]
            CHANGE_CIPHER_SPEC [
                value: binary/read inp 'UI8
                if value != 1 [
                    log-error ["*** CHANGE_CIPHER_SPEC value should be 1 but is:" value]
                    ctx/critical-error: 'Handshake_failure
                    return false
                ]
                either ctx/TLS13? [
                    ; TLS 1.3: ignore change cipher spec (compatibility message)
                    ; Not included in or used by the transcript hash validation process!
                    log-debug "Ignoring TLS 1.3 compatibility ChangeCipherSpec"
                ][
                    unless integer? ctx/extensions/key_share [
                        ctx/handshake?: false
                        ctx/cipher-spec-set: 2
                    ]
                ]
                if integer? ctx/extensions/key_share [
                    ctx/reading?: false
                ]

            ]
            ALERT [
                log-debug ["ALERT len:" :len "ctx/cipher-spec-set:" ctx/cipher-spec-set]
                unless data [
                    log-error "Failed to decode ALERT message!"
                    ;@@ TODO: inspect how it's possible that decrypt failes
                    ;@@ problem is when CHACHA20_POLY1305 is used.
                    ctx/critical-error: none
                    ctx/protocol: 'APPLICATION ; content is reported to higher level
                    continue
                ]
                level: data/1
                id:    data/2

                level: any [*Alert-level/name level  join "Alert-" level ]
                name:  any [*Alert/name id  'Unknown]
                
                ;@@ do some actions here....
                ctx/critical-error: either level = 'WARNING [false][name]
                either id = 0 [
                    ; server done
                    ctx/reading?: false
                    ctx/protocol: 'APPLICATION
                    log-info "Server done"
                ][
                    log-more ["ALERT:" level "-" replace/all form name #"_" #" "]
                ]
            ]
        ]

        ;?? ctx/critical-error
        if ctx/critical-error [ return false ]
        if end <> index? inp/buffer [
            log-error ["Record end mismatch:^[[22m" end "<>" index? inp/buffer]
            ctx/critical-error: 'Record_overflow
            return false
        ]
        ;?? ctx/reading?
        unless ctx/reading? [
            ;? ctx/in/buffer
            log-debug ["Reading finished!"]
            if all [
                not ctx/server?
                integer? ctx/extensions/key_share
            ][
                if ctx/hello-retry-request [
                    log-error "Only one HelloRetryRequest is permitted per handshake!"
                    cause-TLS-error 'Unexpected_message
                ]
                log-info "Retry Hello..."
                ctx/state: 'HELLO_RETRY
                ctx/ecdh-group: *EllipticCurves/name ctx/extensions/key_share
                ctx/hello-retry-request: true
                prepare-client-hello ctx
                do-TCP-write ctx
                ctx/reading?: false
                return false
            ]
            
            ;log-----
            return true
        ]
    ]

    ;?? ctx/state
    log-debug "continue reading..."
    unless empty? ctx/in/buffer [
        ; keeping rest of unprocessed data for later use
        ctx/rest: copy ctx/in/buffer
    ]
    return true
]


prepare-client-hello: function [
    ;; Prepares CLIENT_HELLO message with supported cipher suites
    ;; Includes extensions for key share, supported groups, etc.
    ctx [object!]
][
    change-state ctx 'CLIENT_HELLO
    with ctx [
        extensions: make binary! 100

        ;- Server Name Indication (extension)
        ;  https://tools.ietf.org/html/rfc6066#section-3
        if all [
            ctx/tcp-port
            host-name: ctx/tcp-port/spec/host
        ][
            host-name: to binary! host-name
            length-name:  length? host-name

            binary/write tail extensions compose [
                UI16  0                ; extension type (server_name=0)
                UI16 (5 + length-name) 
                UI16 (3 + length-name)
                UI8   0                ; host_name type
                UI16BYTES :host-name
            ]
        ]

        ;length: 2 + length? supported-elliptic-curves
        ;binary/write tail extensions [
        ;    UI16 10
        ;    UI16 :length
        ;    UI16BYTES :supported-elliptic-curves
        ;]
        ;- Supported Groups (extension)
        encode-extension/length extensions 10 supported-elliptic-curves

        ;- Supported Signature Algorithms (extension)
        encode-extension/length extensions 13 supported-signature-algorithms

        ;- TLS1.3 - supported_version - list TLS 1.3 first, then 1.2 (for fallback)
        append extensions #{002B 0005 04 0304 0303}
        ;length: 2 + length? supported-elliptic-curves
        ;binary/write tail extensions [
        ;    UI16 43
        ;    UI16 :length
        ;    UI16BYTES :supported-elliptic-curves
        ;]

        ;- TLS1.3 - key_share
        ; so far sending just one key....
        curve: first supported-groups
        dh-key:  ecdh/init none ecdh-group: any [ecdh-group curve]
        pub-key: ecdh/public dh-key ;= shared secret
        curve:  *EllipticCurves/:ecdh-group
        key-share: clear #{}
        binary/write key-share [
            UI16      :curve
            UI16BYTES :pub-key
        ]
        ;?? dh-key
        encode-extension/length extensions 51 key-share 
        log-debug ["Client key_share:" *EllipticCurves/name curve "public:" pub-key]

        ;- Other extensions...
        append extensions #{
            ;- Session ticket           
            ;0023 0000        ;= no ticket
            ;- Supported Point Formats  
            000B 0004 03 000102 ;=  uncompressed, ansiX962_compressed_prime,ansiX962_compressed_char2
            ;- Renegotiation Info       
            ; The presence of this extension prevents a type of attack performed with TLS renegotiation. 
            ; https://kryptera.se/Renegotiating%20TLS.pdf
            ; Advertise it, but refuse renegotiation
            FF01 0001 00 ;= (extensionID, 1 byte length, zero byte)
            ;- Encrypt then MAC         
            ; The client indicates it can support EtM, which prevents certain vulnerabilities in earlier versions of TLS.
            ; In TLS 1.3 this mechanism is always used, so this extension will have no effect in this session.
            ;0016 0000
            ;- Extended Master Secret   
            ; The client indicates support for extra cryptographic operations which prevent vulnerabilities in earlier versions of TLS (see RFC 7627 for details).
            ; In TLS 1.3 the vulnerabilities are no longer present, so this extension will have no effect in this session.
            ;0017 0000
            ;- compress_certificate     
            ;001B 0003 02 0001 ; zlib compression

            ;- psk_key_exchange_modes   
            002D 0002 0101  ;psk_dhe_ke
        }

        ;- Signed certificate timestamp (extension)
        ; The client provides permission for the server to return a signed certificate timestamp. 

        ; This form of the client sending an empty extension is necessary because it is a fatal error
        ; for the server to reply with an extension that the client did not provide first. Therefore 
        ; the client sends an empty form of the extension, and the server replies with the extension 
        ; populated with data, or changes behavior based on the client having sent the extension.
        append extensions #{0012 0000}


        ;precomputing the extension's lengths so I can write them in one WRITE call
        length-extensions: length? extensions
        length-message:    73 + length-extensions + length? suported-cipher-suites-binary
        length-record:      4 + length-message

        unless session-id [
            binary/write session-id: make binary! 32 [RANDOM-BYTES 32]
        ]

        binary/write out [
            UI8       22                  ; protocol type (22=Handshake)
            UI16      0#0301              ; minimal protocol version (TLS1.0)
            UI16      :length-record      ; length of SSL record data
            ;client-hello message:
            UI8       1                   ; protocol message type   (1=ClientHello)
            UI24      :length-message     ; protocol message length
            UI16      :legacy-version     ; legacy supported client version (TLS1.2)
            
            ;-- It's not recommended to use unix-time timestamp here anymore!
            ;-- https://datatracker.ietf.org/doc/html/draft-mathewson-no-gmtunixtime-00
            ;@@ UNIXTIME-NOW RANDOM-BYTES 28  ; random struct
            ;-- So let's use just fully random struct..
            RANDOM-BYTES 32               ; random struct

            UI8BYTES  :session-id         ; session ID length
            UI16BYTES :suported-cipher-suites-binary
            UI8       1                   ; compression method length
            UI8       0                   ; no compression
            ;extensions
            UI16BYTES :extensions
        ]

        out/buffer: head out/buffer
        
        locale-random: copy/part (at out/buffer 12) 32
        TLS-update-messages-hash ctx (at out/buffer 6) (4 + length-message) ;@@ TODO review!
        log-more [
            "W[" ctx/seq-write "] Bytes:" length? out/buffer "=>"
            "record:"     length-record
            "message:"    length-message
            "extensions:" length-extensions
            "signatures:" length? supported-signature-algorithms
        ]
        log-more ["W[" ctx/seq-write "] CRandom:^[[32m" locale-random]
    ]
]

prepare-finished-message: function [
    ;; Prepares a FINISHED handshake message, including necessary key switching for post-handshake traffic.
    ctx [object!]
][
    either ctx/TLS13? [
        with ctx [
            log-debug "Send CHANGE_CIPHER_SPEC record (middlebox compatibility mode)"
            ;; This 'CHANGE_CIPHER_SPEC record served a purpose in earlier versions on TLS but is no longer needed.
            ;; In "middlebox compatibility mode" this record is sent to help disguise the session as a TLS 1.2 session.
            binary/write out [
                UI8  20        ; protocol type (20=ChangeCipherSpec)
                UI16 :legacy-version
                UI16 1         ; length of SSL record data
                UI8  1         ; CCS protocol type
            ]
            ;? out

            log-debug "Send Client FINISHED"
            binary/write plain: copy #{} [
                UI8   0#14 ;Finished
                UI24BYTES :verify-data
            ]
            prepare-wrapped-record ctx plain 0#16

            switch-to-app-encrypt ctx
            protocol: 'APPLICATION
        ]
    ][
        change-state ctx 'FINISHED

        seed: get-transcript-hash ctx _ ;read ctx/sha-port

        unencrypted: rejoin [
            #{14}       ; protocol message type (20 = Finished)
            #{00000C}   ; protocol message length (12 bytes)
            prf :ctx/sha-port/spec/method either ctx/server? ["server finished"]["client finished"] seed ctx/master-secret  12
        ]
        
        TLS-update-messages-hash ctx unencrypted
        encrypt-handshake-msg ctx unencrypted
    ]
]


decode-server-hello: function [
    ;; Parses a TLS ServerHello message and updates protocol state and cipher suite selection.
    ctx     [object!]
    message [binary!]
][
    assert-prev-state ctx [CLIENT_HELLO]
    with ctx [
        if any [
            error? try [
                binary/read message [
                    server-version: UI16
                    remote-random:  BYTES 32
                    session-id:     UI8BYTES                        
                    cipher-suite:   UI16
                    compressions:   UI8BYTES ;<- must be empty
                    extensions:     UI16BYTES
                    pos:            INDEX
                ]
            ]
            32 < length? session-id  ;@@ limit session-id size; TLSe has it max 32 bytes
        ][
            log-error "Failed to read server hello."
            cause-TLS-error 'Handshake_failure
        ]

        log-more ["R[" seq-read "] Version:" *Protocol-version/name server-version "cipher-suite:" *Cipher-suite/name cipher-suite]
        log-more ["R[" seq-read "] SRandom:^[[32m" remote-random ]
        log-more ["R[" seq-read "] Session:^[[32m" session-id]

        if server-version <> version [
            log-error [
                "Version required by server:" server-version
                "is not same like clients:" version
            ]
            
            ; protocol downgrade (to v1.1) is not allowed now, would have to find out, how to make it
            if server-version <> version [
                cause-TLS-error 'Protocol_version
            ]

            version: server-version
        ]

        unless empty? compressions [
            log-more ["R[" seq-read "] Compressions:^[[1m" compressions ]
            log-error "Compression flag must be 0!"
            cause-TLS-error 'Illegal_parameter
        ]

        unless TLS-init-cipher-suite ctx [
            log-error "Unsupported cipher suite!"
            cause-TLS-error 'Illegal_parameter
        ]

        ;-- extensions handling
        extensions: decode-extensions ctx :extensions
        case/all [
            integer? extensions/key_share [
                ;; Server's Hello Retry Request
                log-info ["Hello Retry Request with key_share type:" *EllipticCurves/name extensions/key_share]
                ;; Transcript hash -> https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1
                ;; Replace CLIENT_HELLO message with a special synthetic handshake message of handshake type
                ;; "message_hash" containing Hash(ClientHello1)
                hash: checksum ctx/context-messages/2 ctx/hash-type
                binary/write clear ctx/context-messages/2  [
                    UI8 254 ;=message_hash
                    UI16 0
                    UI8BYTES :hash
                ]
            ]
            all [
                extensions/supported_versions == 0#0304 ;; Server accepts TLS1.3
                ;; key must be same type like used in CLIENT_HELLO 
                handle? dh-key
                block? extensions/key_share
                ;extensions/key_share/1 = probe ecdh/curve dh-key
            ][
                log-info "Using TLS v1.3"
                version: 0#0304
                TLS13?: true
                pre-secret: ecdh/secret dh-key extensions/key_share/2
                log-more ["Elyptic curve^[[1m" extensions/key_share/1 "^[[22mdata (pre-secret):" pre-secret]
                TLS-key-expansion ctx
            ]
        ]
        false ;= no error
    ]
]
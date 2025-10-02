Rebol [
    title: "TLS Server Implementation"
    file:  %tls-server.reb
    license: MIT ;= SPDX-License-Identifier
]

TLS-server-awake: func [
    ;; Handles initial server socket events such as a new incoming connection and sets up client socket state.
    event [event!]
    /local port info serv
][
    log-more ["AWAKE Server:^[[1m" event/type]
    ;; Determine action based on TCP port event type
    switch event/type [
        accept [
            ;; New TCP connection accepted
            port: first serv: event/port  ;; 'serv' is the server listener port; extract client port
            ;; Obtain client connection details
            info: query port [remote-ip remote-port]
            ;; Initialize a new TLS context for this client
            port/extra: make TLS-context [
                tcp-port: port                      ;; Underlying TCP port
                tls-port: serv/parent               ;; Parent TLS port
                server?:  true                      ;; Mark context as server side
                state:   'CLIENT_HELLO              ;; Start handshake expecting ClientHello
                version:  serv/extra/version        ;; Record negotiated TLS version
            ]
            ;; Update port metadata for identification
            port/spec/title: "TLS Server's client"
            port/spec/ref: rejoin [tcp:// info/remote-ip #":" info/remote-port]
            ;; Set the event handler for this client port
            port/awake: :TLS-server-client-awake
            ;; Begin reading from the new client port to start handshake
            read port
        ]
    ]
    false  ;; Return false to indicate no further action for this event
]


TLS-server-client-awake: function [
    ;; Processes client socket events for server-side connections, handling record reading, writing, and dispatching.
    event [event!]
][
    TCP-port: event/port
    ;? TCP-port
    ctx: TCP-port/extra
    log-debug ["Server's client awake event:" event/type "state:" ctx/state ctx/server?]
    switch event/type [
        read [
            error: try [
                complete?: TLS-read-data ctx TCP-port/data
                if ctx/critical-error [ cause-TLS-error ctx/critical-error ]
                log-debug ["==============Read complete?" complete? "state:" ctx/state]
                either complete? [
                    switch ctx/state [
                        CLIENT_HELLO [
                            prepare-server-hello ctx
                            unless ctx/hello-retry-request [
                                TLS-key-expansion ctx
                                prepare-change-cipher-spec ctx
                                prepare-server-encrypted-extensions ctx
                                prepare-server-certificate ctx
                                either ctx/TLS13? [
                                    prepare-server-handshake-finish ctx
                                ][
                                    prepare-server-hello-done ctx
                                ]
                            ]
                            write TCP-port head ctx/out/buffer
                        ]
                        FINISHED [
                            ctx/cipher-spec-set: 2 
                            log-more "FINISHED"
                            change-state ctx 'APPLICATION
                            log-more "Start reading real data..."
                            read TCP-port
                        ]
                        APPLICATION [
                            ;; Report real application data to the parent
                            TCP-port/parent/actor/On-Read TCP-port
                        ]
                    ]
                ][
                    read TCP-port
                ]
                return false
            ]
            ; on error:
            if ctx [ log-error ctx/error: error ]
            ;dispatch-event 'error TLS-port
            do-TLS-close TCP-port
            return true
        ]
        wrote [
            either ctx/protocol = 'APPLICATION [
                TCP-port/parent/actor/On-Wrote TCP-port
            ][
                read TCP-port
            ]
            return false
        ]
        close [
            do-TLS-close TCP-port
            return true
        ]
    ]
    false
]

prepare-server-hello: function [
    ;- At this point we received (and parsed) new clients CLIENT_HELLO.
    ;; Purpose of this function is to prepare server's reply which is later sent to client.
    ctx [object!]
][
    change-state ctx 'SERVER_HELLO
    with ctx [
        ;?? extensions
        key_share: none
        if all [
            block? extensions/supported_versions
            block? extensions/key_share
            find extensions/supported_versions 0#0304 ;; TLS1.3
        ][
            log-info "Using TLS v1.3"
            version: 0#0304
            TLS13?: true

            ;- TLS1.3 - key_share
            key_share: make binary! 32
            curve: extensions/key_share/1  ;; should be name of the known curve
            either find supported-groups curve [
                dh-key:  ecdh/init none curve
                pub-key: ecdh/public dh-key
                curve:  *EllipticCurves/:curve ;; convert to integer
                binary/write key_share [
                    UI16      :curve
                    UI16BYTES :pub-key
                ]
                pre-secret: ecdh/secret dh-key extensions/key_share/2
                log-more ["Elyptic curve^[[1m" extensions/key_share/1 "^[[22mdata (pre-secret):" pre-secret]
                ctx/hello-retry-request: none
            ][
                change-state ctx 'SERVER_HELLO_RETRY
                ?? supported-groups
                ?? ctx/extensions/supported_groups
                hello-retry-request: true
                ecdh-group: attempt [
                    curve: first union supported-groups ctx/extensions/supported_groups
                    *EllipticCurves/:curve
                ]
                unless ecdh-group [
                    cause-TLS-error 'Insufficient_security ;@@ or other?
                ]
                log-info ["Server requests HelloRetry with elliptic group:" ecdh-group]
                binary/write key_share [
                    UI16      :ecdh-group
                ]
            ]
        ]

        binary/init out none ;reset output buffer


        ;?? session-id
        ;?? extensions
        server-extensions: #{
        ;   00000000         ; server_name
        }
        if find extensions 'ec_point_formats [
            append server-extensions #{000B000403000102}
        ]
        if find extensions 'renegotiation_info [
            append server-extensions #{FF01000100}
        ]

        if TLS13? [
            append server-extensions #{002B 0002 0304}
            if key_share [
                encode-extension server-extensions 51 key_share 
            ]
        ]
        ;?? server-extensions



        binary/write out [
         pos-start:
            UI8       22        ; protocol type (22=Handshake)
            UI16      0#0301    ; protocol version (minimal supported)
         pos-record-len:
            UI16      0         ; will be set later
         pos-record:
            ;server-hello message:
            UI8       2         ; protocol message type (2=ServerHello)
         pos-message-len:
            UI24      0         ; will be set later
            UI16      0#0303    ; prefered version by server
        ]
        binary/write out either/only hello-retry-request [
            :HRR-magic
        ][
            UNIXTIME-NOW RANDOM-BYTES 28  ; random struct
        ]
        binary/write out [
            UI8BYTES  :session-id
            UI16      :cipher-suite
            UI8       0         ;no compression
            UI16BYTES :server-extensions
         pos-end:
        ]
        locale-random: copy/part (at out/buffer 12) 32
        log-more ["W[" ctx/seq-write "] SRandom:^[[32m" locale-random]
        log-more ["W[" ctx/seq-write "] Session:^[[32m" session-id]
        
        ;; fill the missing lengths
        binary/write out compose [
            AT :pos-record-len  UI16 (length-record:  pos-end - pos-record)
            AT :pos-message-len UI24 (length-message: length-record - 4)
            AT :pos-end
        ]
        ;; and count record's hash
        TLS-update-messages-hash/part ctx (at head out/buffer :pos-record) :length-record ;@@ remove /part
        log-more [
            "W[" ctx/seq-write "] Bytes:" pos-end - pos-start "=>"
            "record:"     length-record
            "message:"    length-message
        ]
    ]
]

prepare-server-certificate: function [
    ;; Prepares the server’s TLS certificate message, and if required, CertificateVerify and/or ServerKeyExchange.
    ctx [object!]
][
    change-state ctx 'CERTIFICATE
    with ctx [
        ; certificates are stored in the server (tpc's parent) settings
        certificates: tls-port/state/certificates
        length: 4 + length? certificates
        record: clear #{}
        binary/write record [
            UI8       11       ; Handshake Type (11 = Certificate)
            UI24      :length  ; Handshake Length
            UI8       0        ; Certificate Request Context Length (0 for server)
            UI24BYTES :certificates
        ]
        encode-handshake-record ctx record
        ;=======================================

        ;; Server Cerfificate Verify...
        if TLS13? [
            change-state ctx 'CERTIFICATE_VERIFY
            to-sign: rejoin [
                server-certificate-verify-context
                ;; Get hash of handshake messages (Client Hello .. Certificate)
                get-transcript-hash ctx 'CERTIFICATE
            ]
            signature: rsa/sign/pss tls-port/state/private-key :to-sign
            ;?? signature
            length: 4 + length? signature
            binary/write clear record [
                UI8       15       ; Handshake Type (11 = Certificate)
                UI24      :length
                UI16      0#0804   ; RSA-PSS-RSAE-SHA256 signature
                UI16BYTES :signature
            ]
            encode-handshake-record ctx record
        ]

        ;=======================================
        if find [ECDHE_RSA ECDHE_ECDSA DHE_RSA] key-method [
            ;; is emphemeral cipher
            change-state ctx 'SERVER_KEY_EXCHANGE
            binary/write clear record [
                UI8       12   ; Handshake Type (12 = ServerKeyExchange)
                UI24      0    ; Handshake Length (will be set later)
            ]

            switch key-method [
                ECDHE_RSA [
                    spec: TCP-port/parent/state
                    ;@@ TODO: make sure, that curve is supported by client!
                    curve: first spec/elliptic-curves
                    dh-key: ecdh/init none curve
                    pub-key: ecdh/public dh-key

                    ;log-more ["Server's ECDHE" curve "pub-key:^[[1m" mold pub-key]

                    curve: *EllipticCurves/:curve  ; converted to integer for writting
                    ;@@ TODO: detect sign-algorithm from the certificate!
                    sign-algorithm: *ClientCertificateType/rsa_sign
                    hash-method-int: *HashAlgorithm/:hash-method

                    binary/write message: clear #{} [
                        BYTES :remote-random
                        BYTES :locale-random
                     pos-msg:
                        UI8      3 ;= ECDHE_RSA
                        UI16     :curve
                        UI8BYTES :pub-key
                    ]
                    signature: rsa/sign/hash spec/private-key :message :hash-method
                    remove/part message (pos-msg - 1) ; removing random bytes
                    binary/write record [
                        BYTES     :message
                        UI8       :hash-method-int
                        UI8       :sign-algorithm
                        UI16BYTES :signature
                    ]
                ] 
            ]

            length: (length? record) - 4
            binary/write next record [UI24 :length]

            encode-handshake-record ctx record
        ]
    ]
]

prepare-server-hello-done: function [
    ;; Prepares a TLS ServerHelloDone handshake message marking handshake completion (pre-TLS 1.3).
    ctx [object!]
][
    change-state ctx 'SERVER_HELLO_DONE
    encode-handshake-record ctx #{0E000000}
]

prepare-server-encrypted-extensions: function [
    ;; Prepares EncryptedExtensions message in TLS 1.3 to communicate negotiation results to client.
    ctx [object!]
][
    change-state ctx 'ENCRYPTED_EXTENSIONS
    encode-handshake-record ctx #{080000020000}
]

prepare-server-handshake-finish: function [
    ;; Prepares and sends the server’s FINISHED handshake message, completing the handshake and switching keys.
    ctx [object!]
][
    change-state ctx 'FINISHED
    with ctx [
        ;?? context-messages
        finished-hash: get-transcript-hash ctx _
        ;; Derive Finished key from client traffic secret to verify server Finished
        finished-key: HKDF-Expand/label hash-type locale-hs-secret #{} mac-size "finished"
        ;; Derive Server Handshake Finished data
        verify-data: checksum/with finished-hash hash-type finished-key
        ;?? verify-data

        binary/write record: clear #{} [
            UI8       20       ; Handshake Type (20 = Finished)
            UI24BYTES :verify-data
        ]
        encode-handshake-record ctx record

        derive-application-traffic-secrets ctx
    ]
]


decode-client-hello: function [
    ;; Parses and processes the client’s ClientHello message, extracting cipher suites, extensions, and keys.
    ctx     [object!]
    message [binary!]
][
    binary/read message [
        client-version: UI16 ; max supported version by client
        ;client-hello message:
        remote-random: BYTES 32 ; random struct
        session-id:    UI8BYTES
        cipher-suites: UI16BYTES
        compressions:  UI8BYTES
        extensions:    UI16BYTES
    ]
    log-debug ["Client requests:" *Protocol-version/name :client-version]
    log-debug ["Client random: ^[[1m" remote-random]
    ctx/remote-random: remote-random
    ctx/session-id: session-id
    unless empty? session-id [
        ;@@ could be used for Session Resumption
        ;https://hpbn.co/transport-layer-security-tls/#tls-session-resumption
        log-debug ["Client session:" session-id]
    ]

    client-cipher-suites: decode-list *Cipher-suite :cipher-suites _
    ?? client-cipher-suites
    foreach cipher client-cipher-suites [
        if find suported-cipher-suites cipher [
            ; store as an integer
            ?? cipher
            ctx/cipher-suite: *Cipher-suite/:cipher
            log-info ["Server choose cipher:" as-yellow ctx/cipher-suite]
            TLS-init-cipher-suite ctx
            break
        ]
    ]
    ; now we should have initialized cipher suites, return error, if not
    unless ctx/crypt-method [
        log-error "No supported cipher-suite!"
        cause-TLS-error 'Handshake_failure
    ]

    if #{00} <> compressions [
        log-error ["Client requests compression:" compressions]
        cause-TLS-error 'Unexpected_message
    ]
    ;? extensions
    ctx/extensions: decode-extensions ctx :extensions

    if all [
        block? ctx/extensions/supported_groups
        block? ctx/extensions/key_share
        none? find ctx/extensions/supported_groups ctx/extensions/key_share/1
    ][
        log-error ["Key_share type^[[22m" ctx/extensions/key_share/1 "^[[1mthat is not listed in supported_groups!"]
        cause-TLS-error 'Illegal_parameter
    ]
    ;if groups: select ctx/extensions 'supported_groups [
    ;]
    ;'clear TCP-port/data
    ctx/reading?: false
]
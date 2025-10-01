Rebol [
    title: "TLS Scheme Implementation"
    file:  %tls-scheme.reb
    license: MIT ;= SPDX-License-Identifier
]

; Port operations
do-TLS-open: func [
    ;; Handles the opening/init state for a TLS port, including TLS context creation and certificate loading.
    port [port!]
    /local spec conn config certs bin der key
][
    log-debug "OPEN"
    if port/state [return port]
    spec: port/spec

    either port? conn: select spec 'conn [
        ;- reusing already prepared TCP connection      
        spec/host: conn/spec/host
        spec/port: conn/spec/port
        if block? spec/ref [
            spec/ref: rejoin [tls:// any [spec/host ""] ":" spec/port]
        ]
    ][
        ;- opening new low level TCP connection         
        conn: make port! [
            scheme: 'tcp
            host:    spec/host
            port:    spec/port
            ref:     rejoin [tcp:// any [host ""] ":" port]
        ]
        if port/parent [
            conn/state: port/parent/state
        ]
        conn/parent: port
    ]

    either spec/host [
        ;- CLIENT connection ---------------------------
        port/extra: conn/extra: make TLS-context [
            tcp-port: conn
            tls-port: port
            version: *Protocol-version/TLS1.2
        ]
        port/data: conn/extra/port-data
        conn/awake: :TLS-client-awake
    ][
        ;- SERVER connection ---------------------------
        spec/ref: rejoin [tls://: spec/port]
        port/spec/title: "TLS Server"
        conn/spec/title: "TLS Server (internal)"
        port/state: conn/extra: object [
            TCP-port: conn
            certificates: none
            private-key:  none
            elliptic-curves: decode-list *EllipticCurves :supported-elliptic-curves _
            version: *Protocol-version/TLS1.2
        ]
        ;? spec
        if config: select spec 'config [
            certs: any [select config 'certificates []]
            unless block? certs [certs: to block! certs]
            bin: binary 4000
            ;binary/write bin reduce ['UI8 length? certs]
            foreach file certs [
                try/with [
                    der: select decode 'pkix read file 'binary
                    binary/write bin [UI24BYTES :der]
                ][
                    log-error ["Failed to import certificate:" file]
                ]
            ]
            binary/write bin [UI16 0] ;= Certificate extensions (none)
            port/state/certificates: bin/buffer
            ;?? port/state/certificates

            if key: select config 'private-key [
                if file? key [try [key: load key]]
                either handle? key [
                    port/state/private-key: key
                ][  log-error ["Failed to import private key:" key] ]
            ]
        ]
        port/actor: context [
            On-Read: func [port [port!] /local data][
                log-debug "TLS On-Read"
                probe to string! data: port/extra/port-data
                either empty? data [
                    do-TLS-read port
                ][
                    do-TLS-write port "HTTP/1.1 200 OK^M^/Content-type: text/plain^M^/^M^/Hello from Rebol using TLS v1.3"
                ]
            ]
            On-Wrote: func [port [port!]][
                dispatch-event 'close port
            ]
        ]
        conn/parent: port
        conn/awake: :TLS-server-awake
    ]
    either open? conn [
        TLS-init-context    conn/extra
        TLS-init-connection conn/extra
    ][
        open conn
    ]
    port
]

do-TLS-close: func [
    ;; Cleans up and closes all state and ports associated with a TLS connection.
    port [port!] /local ctx parent
][
    log-debug "CLOSE"
    unless ctx: port/extra [return port]
    parent: port/parent
    log-debug "Closing port/extra/tcp-port"
    close ctx/tcp-port
    if port? ctx/encrypt-port [ close ctx/encrypt-port ]
    if port? ctx/decrypt-port [ close ctx/decrypt-port ]
    ctx/encrypt-port: none
    ctx/decrypt-port: none
    ctx/tcp-port/awake: none
    ctx/tcp-port: none
    ctx/tls-port: none
    port/extra: none
    log-more "Port closed"
    if parent [
        insert system/ports/system make event! [type: 'close port: parent]
    ]
    port
]

do-TLS-read: func [
    ;; Handles a read event for a TLS port, triggering record receive from the underlying TCP port.
    port [port!]
][
    log-debug "READ"
    read port/extra/tcp-port
    port
]

do-TLS-write: func [
    ;; Handles a write event for a TLS port, triggering record send to the underlying TCP port.
    port  [port!]
    value [any-string! binary!]
     /local ctx
][
    log-debug "WRITE"
    ;?? value
    ctx: port/extra
    ;? ctx
    if ctx/protocol = 'APPLICATION [
        binary/init ctx/out none ;resets the output buffer
        ;@@ There is a size limit for application data 16KiB!
        while [not tail? value][
            prepare-application-data ctx copy/part :value 16384
            value: skip value 16384
        ]
        do-TCP-write ctx
        return port
    ]
]

do-TCP-write: func[
    ;; Writes bytes to the TCP port associated with a TLS connection.
    ctx [object!]
][
    log-debug ["Writing bytes:" length? ctx/out/buffer]
    ;?? ctx/out/buffer
    clear ctx/port-data
    write ctx/tcp-port ctx/out/buffer
    binary/init ctx/out none ;resets the output buffer
    ctx/reading?: true
]

prepare-application-data: func [
    ;; Prepares and sends an application_data record (encrypted if appropriate) through the TLS protocol.
    ctx [object!]
    message [binary! string!]
][
    ;log-debug "application-data"
    log-more ["W[" ctx/seq-write "] application data:" length? message "bytes"]
    ;prin "unencrypted: " ?? message
    ;? ctx/TLS13?
    either ctx/TLS13? [
        prepare-wrapped-record ctx to binary! message 23
    ][  ;; TLS1.2
        message: encrypt-tls-record ctx to binary! message
        ;prin "encrypted: " ?? message
        with ctx [
            binary/write out [
                UI8       23        ; protocol type (23=Application)
                UI16      :legacy-version  ; protocol version
                UI16BYTES :message 
            ]
            ++ seq-write
        ]
    ]
]

prepare-alert-close-notify: func [
    ;; Prepares a close_notify alert message to signal orderly TLS shutdown to the peer.
    ctx [object!]
][
    ;@@ Not used/tested yet! It should be replaced with ALERT-notify with CLOSE as possible type
    log-more "alert-close-notify"
    message: encrypt-tls-record ctx #{0100} ; close notify
    with ctx [
        binary/write out [
            UI8       21               ; protocol type (21=Alert)
            UI16      :legacy-version  ; protocol version
            UI16BYTES :message
        ]
    ]
]


handshake-finished: func [
    ;; Marks handshake completion and dispatches connection success to the parent port/scheme.
    ctx [object!]
][
    log-----
    log-info "Handshake finished"
    ctx/handshake?: false
    dispatch-event 'connect ctx/TLS-port
]

tls-config: func [
    spec
][
    foreach [key value] spec [
        switch :key [
            groups
            supported-groups
            [
                if block? :value [
                    clear supported-elliptic-curves
                    clear supported-groups
                    foreach curve :value [
                        ;; Collect only curves, which are available.
                        if find system/catalog/elliptic-curves curve [
                            append supported-groups curve
                            binary/write tail supported-elliptic-curves [UI16BE :*EllipticCurves/:curve]
                        ]
                    ]
                ] ;TODO: report error?
            ]

            verbose
            verbosity
            [
                tls-verbosity :value
            ]
        ]
    ]
]


;- Scheme registration
sys/make-scheme [
    name:  'tls
    title: "TLS protocol v1.3"
    spec:  make system/standard/port-spec-net [
        supported-groups: [
        ;;  curves in the prefered order!
            curve25519 ;0#001D Very strong security with high performance.
            curve448   ;0#001E Stronger security than curve25519, but slower.
            secp521r1  ;0#0019 Very high security but slower than curve25519.
            secp384r1  ;0#0018 Good security and performance balance.
            secp256r1  ;0#0017 Widely supported and fast. Basis for most elliptic curve cryptography today.
            bp512r1    ;0#001C Strong security, less common support.
            bp384r1    ;0#001B Similar to secp384r1 but less widely supported.
            bp256r1    ;0#001A Lower security profile, used in niche cases.
            secp256k1  ;0#0016 Medium security, great for specific use cases.
            secp224r1  ;0#0015 Lower security, generally discouraged.
            secp224k1  ;0#0014 Even less common, shorter keys, limited TLS use.
        ;   secp192r1  ;0#0013 Weak security by today’s standards, usually deprecated.
        ]
    ]
    actor: reduce/no-set [
        read:    :do-TLS-read
        write:   :do-TLS-write
        open:    :do-TLS-open
        close:   :do-TLS-close
        query:   func [port [port!]][all [port/extra query port/extra/tcp-port]]
        open?:   func [port [port!]][all [port/extra open? port/extra/tcp-port]]
        copy:    func [port [port!]][if port/data [copy port/data]]
        length?: func [port [port!]][either port/data [length? port/data][0]]
    ]
    set-verbose: :tls-verbosity
    config: :tls-config

]

Rebol [
    title: "TLS Cryptographic Functions"
    SPDX-License-Identifier: Apache-2.0
    file: %tls-crypto.reb
]


;- TLS1.3 related functions

HKDF-Extract: func [
    ;; Performs the HKDF-Extract operation used to derive pseudorandom key material from input and salt.
    hash [word!]
    salt [binary!]
    ikm  [binary!]    ;; Input keying material
    return: [binary!] ;; Pseudorandom key (PRK)
][
    checksum/with ikm hash salt
]

HKDF-Expand: func [
    ;; Performs the HKDF-Expand operation to generate key material from a pseudorandom key and input data.
    ;; HKDF-Expand(PRK, info, L) -> OKM
    hash   [word!] 
    prk    [binary!]  ;; Pseudorandom key of at least HashLen bytes
    data   [binary!]  ;; Application specific information
    length [integer!] ;; Length of output keying material in bytes
    /label
    context [string!] ;; Optional context label
    return: [binary!] ;; Output keying material (OKM)
    /local tmp i out 
][
    if label [
        label: ajoin ["tls13 " context]
        tmp: make binary! 64
        binary/write tmp [
            UI16 :length
            UI8BYTES :label
            UI8BYTES :data
        ]
        data: tmp
    ]
    out: make binary! length
    tmp: #{} i: 0
    while [length > length? out][
        ++ i
        tmp: checksum/with rejoin [tmp data i] hash prk
        append out tmp
    ]
    head clear atz out length
]




;- TLS1.2 legacy functions

prf: function [
    ;; Implements a pseudo-random function suitable for TLS key derivation.
    hash    [word!]
    label   [string! binary!]
    seed    [binary!]
    secret  [binary!]
    output-length [integer!]
][
    ; The seed for the underlying P_<hash> is the PRF's seed appended to the
    ; label.  The label is hashed as-is, so no null terminator.
    ;
    ; PRF(secret, label, seed) = P_<hash>(secret, label + seed)
    ;

    log-more ["PRF" hash mold label "len:" output-length]
    seed: join to binary! label seed

    ; TLS 1.2 includes the pseudorandom function as part of its cipher
    ; suite definition.  No cipher suites assume the md5/sha1 combination
    ; used above by TLS 1.0 and 1.1.  All cipher suites listed in the
    ; TLS 1.2 spec use `P_SHA256`, which is driven by the single SHA256
    ; hash function: https://tools.ietf.org/html/rfc5246#section-5

    p-sha256: make binary! output-length
    a: seed ; A(0)
    while [output-length >= length? p-sha256][
        a: checksum/with a :hash :secret
        append p-sha256 checksum/with append copy :a :seed :hash :secret
        ;?? p-sha256
    ]
    ;trim the result to required output length
    clear at p-sha256 (1 + output-length)
    ;log-more ["PRF result length:" length? p-sha256 mold p-sha256]
    p-sha256
]

TLS-key-expansion: func [
    ;; Runs the TLS key schedule to derive handshake and traffic secrets, keys, and IVs for the TLS connection.
    ctx [object!]
    /local rnd1 rnd2 key-expansion sha
    derived_secret empty_hash hello_hash early_secret
    handshake_secret client_secret server_secret
][
    with ctx [
        sha: ctx/hash-type
        log-debug ["===================TLS-key-expansion" sha]
        ;-- make all secure data
        either TLS13? [
            ;- TLS1.3
            unless derived_secret: derived-secrets/:sha [
                ;; If we haven't yet derived this hash's secret, initialize necessary values.
                empty-hash/:sha: checksum #{} :sha
                zero-keys/:sha: append/dup clear #{} 0 :mac-size
                early_secret:  HKDF-Extract :sha #{} zero-keys/:sha
                ;; Compute the 'derived' secret using HKDF-Expand-Label, providing separation
                ;; between different phases of the key schedule. ('mac-size' is the digest size.)
                ;; This value is a well-known intermediate value in the TLS 1.3 key derivation path.
                derived-secrets/:sha:
                derived_secret: HKDF-Expand/label :sha early_secret empty-hash/:sha mac-size "derived"
            ]
            hello_hash: get-transcript-hash ctx _
            handshake-secret: HKDF-Extract      :sha derived_secret :pre-secret
            ;? handshake-secret
            either server? [
                locale-hs-secret:  HKDF-Expand/label :sha handshake-secret hello_hash mac-size "s hs traffic"
                remote-hs-secret:  HKDF-Expand/label :sha handshake-secret hello_hash mac-size "c hs traffic"
            ][
                locale-hs-secret:  HKDF-Expand/label :sha handshake-secret hello_hash mac-size "c hs traffic"
                remote-hs-secret:  HKDF-Expand/label :sha handshake-secret hello_hash mac-size "s hs traffic"
            ]
            locale-hs-key:     HKDF-Expand/label :sha locale-hs-secret #{} crypt-size "key"
            remote-hs-key:     HKDF-Expand/label :sha remote-hs-secret #{} crypt-size "key"
            locale-hs-IV:      HKDF-Expand/label :sha locale-hs-secret #{} IV-size + IV-size-dynamic "iv"
            remote-hs-IV:      HKDF-Expand/label :sha remote-hs-secret #{} IV-size + IV-size-dynamic "iv"
            cipher-spec-set: 2
            ;; In TLS1.3 additional data used for AEAD has only 5 bytes
            aad-length: 5
        ][  ;- TLS1.2
            either server? [
                rnd1: append copy ctx/remote-random ctx/locale-random
                rnd2: append copy ctx/locale-random ctx/remote-random
            ][
                rnd2: append copy ctx/remote-random ctx/locale-random
                rnd1: append copy ctx/locale-random ctx/remote-random
            ]
            
            master-secret: prf :sha "master secret" rnd1 pre-secret 48
            key-expansion: prf :sha "key expansion" rnd2 master-secret (mac-size + crypt-size + iv-size) * 2

            either server? [
                unless is-aead? [
                   remote-mac: take/part key-expansion mac-size
                   locale-mac: take/part key-expansion mac-size
                ]
                remote-hs-key: take/part key-expansion crypt-size
                locale-hs-key: take/part key-expansion crypt-size
                remote-hs-IV:  take/part key-expansion iv-size
                locale-hs-IV:  take/part key-expansion iv-size
            ][
                unless is-aead? [
                   locale-mac: take/part key-expansion mac-size
                   remote-mac: take/part key-expansion mac-size
                ]
                locale-hs-key: take/part key-expansion crypt-size
                remote-hs-key: take/part key-expansion crypt-size
                locale-hs-IV:  take/part key-expansion iv-size
                remote-hs-IV:  take/part key-expansion iv-size
            ]
            if IV-size-dynamic > 0 [
                append/dup locale-hs-IV 0 IV-size-dynamic
                append/dup remote-hs-IV 0 IV-size-dynamic
            ]
        ]
        log-more ["locale-IV: ^[[32m" locale-hs-IV ]
        log-more ["locale-mac:^[[32m" locale-mac]
        log-more ["locale-key:^[[32m" locale-hs-key]
        log-more ["remote-IV: ^[[32m" remote-hs-IV ]
        log-more ["remote-mac:^[[32m" remote-mac]
        log-more ["remote-key:^[[32m" remote-hs-key]

        encrypt-port: open [
            scheme:      'crypt
            algorithm:   :crypt-method
            init-vector: :locale-hs-IV
            key:         :locale-hs-key
        ]
        decrypt-port: open [
            scheme:      'crypt
            direction:   'decrypt
            algorithm:   :crypt-method
            init-vector: :remote-hs-IV
            key:         :remote-hs-key
        ]
        ;@@ TODO: could be supported in the spec directly, but that is not implemented yet!
        modify encrypt-port 'aad-length :aad-length
        modify decrypt-port 'aad-length :aad-length
        if tag-length > 0 [
            modify decrypt-port 'tag-length :tag-length
            modify encrypt-port 'tag-length :tag-length
        ]
        ; not needed anymore...
        pre-secret: locale-hs-key: remote-hs-key: none
        seq-write: seq-read: 0 
    ]
]


wrap-record: func [
    ;; Encrypts and wraps a TLS record (plain message) for transmission using the current keys and nonces.
    ctx       [object! ]  ;; TLS context containing encryption keys and state
    plaintext [binary! ]  ;; Raw application or handshake data to encrypt
    type      [integer!]  ;; Original TLS content type (22=handshake, 23=app_data)
    /locale
     length         ;; Length of plaintext + content type + auth tag
     nonce          ;; AEAD nonce for TLS 1.3 encryption
     seq-bytes      ;; Sequence number in binary format
     aad            ;; Additional Authenticated Data buffer

][with ctx [
    ;; TLS 1.3 Inner Plaintext Construction
    ;; Append the real content type to plaintext (becomes TLSInnerPlaintext)
    ;; This hides the actual record type from network observers
    plaintext: append copy plaintext type
    ;; Calculate total ciphertext length: plaintext + content_type + auth_tag
    length: tag-length + length? plaintext

    ;; Construct Additional Authenticated Data (AAD) for AEAD encryption
    ;; AAD format: fake_content_type + legacy_version + ciphertext_length
    binary/write aad: clear #{} [
        UI8   23               ;; Always use application_data (23) as outer type
        UI16  :legacy-version  ;; Legacy record version (0#0303 for TLS 1.2)
        UI16  :length          ;; Total length including auth tag
    ]
    ;; Handle different AEAD cipher nonce construction
    if crypt-method != 'CHACHA20-POLY1305 [
        ;; Most AEAD ciphers (AES-GCM, AES-CCM) use IV XOR sequence_number
        
        ;; Select appropriate IV based on content type:
        ;; - Application data (23): use application traffic IV
        ;; - Handshake data (22): use handshake traffic IV  
        nonce: append clear #{} either type = 23 [locale-ap-IV][locale-hs-IV]
        ;; Format write sequence number as 12-byte big-endian value
        ;; (padded with zeros to match IV length)
        seq-bytes: #{000000000000000000000000}
        binary/write seq-bytes [ATz 4 UI64BE :seq-write]
        ;; Create per-record nonce: IV XOR sequence_number
        ;; This ensures each record has a unique nonce
        nonce: nonce xor seq-bytes 
        ;; Configure encryption port with the computed nonce
        modify encrypt-port 'iv nonce
        ;; Provide AAD to the AEAD encryption algorithm
        write encrypt-port aad
        ;?? nonce ?? aad ?? seq-write
    ]
    ++ seq-write
    ;; Note: CHACHA20-POLY1305 uses a different nonce construction method
    ;; and is handled separately by the encrypt-port implementation
    
    ;; Perform AEAD encryption: plaintext + content_type -> ciphertext + auth_tag
    ;; Returns encrypted data with authentication tag appended
    read update write encrypt-port :plaintext
]]


encrypt-tls-record: function [
    ;; Takes plaintext data and the message type, encrypts it as a TLS record, and prepares it for sending.
    ctx     [object!]
    content [binary!]
    /type
        msg-type [integer!] "application data is default"
][
    log-debug ["--encrypt-tls-record--" as-red ctx/seq-write]
    msg-type: any [msg-type 23] ;-- default application
    ;?? content

    with ctx [
        ; record header
        length: length? content
        binary/write bin [
            UI64  :seq-write
            UI8   :msg-type
            UI16  :legacy-version
            UI16  :length
        ]
        either is-aead? [
            aad: bin/buffer
            either crypt-method = 'CHACHA20-POLY1305 [
                write encrypt-port :aad
                ; on next line are 3 ops.. encrypting content, counting its MAC and getting the result  
                encrypted: read update write encrypt-port content
            ][
                ; update dynamic part of the IV
                binary/write locale-hs-IV [ATz :IV-size UI64be :seq-write]
                
                log-more ["locale-IV:   ^[[32m" locale-hs-IV]
                log-more ["AAD:        ^[[32m" bin/buffer]
                
                modify encrypt-port 'iv locale-hs-IV
                write  encrypt-port  :aad
                encrypted: read update write encrypt-port content
                if IV-size-dynamic > 0 [
                    insert encrypted copy/part skip locale-hs-IV :IV-size :IV-size-dynamic
                ]
            ]
        ][

            ;@@ GenericBlockCipher: https://tools.ietf.org/html/rfc5246#section-6.2.3.2
            ; "The Initialization Vector (IV) SHOULD be chosen at random, and
            ;  MUST be unpredictable.  Note that in versions of TLS prior to 1.1,
            ;  there was no IV field, and the last ciphertext block of the
            ;  previous record (the "CBC residue") was used as the IV.  This was
            ;  changed to prevent the attacks described in [CBCATT].  For block
            ;  ciphers, the IV length is SecurityParameters.record_iv_length,
            ;  which is equal to the SecurityParameters.block_size."
            ;
            binary/write clear locale-hs-IV [RANDOM-BYTES :block-size]
            modify encrypt-port 'init-vector locale-hs-IV

            ;?? ctx/seq-write
            log-more ["locale-IV: ^[[32m" locale-hs-IV]
            log-more ["locale-mac:^[[32m" locale-mac]
            log-more ["hash-type:^[[32m" hash-type]

            ; Message Authentication Code
            ; https://tools.ietf.org/html/rfc5246#section-6.2.3.1

            binary/write bin content
            ; computing MAC on the header + content 
            ;?? bin/buffer
            MAC: checksum/with bin/buffer ctx/hash-type ctx/locale-mac
            ; padding the message to achieve a multiple of block length
            len: length? append content MAC
            ;?? MAC ?? content ??  block-size ?? len
            if block-size [
                ; add the padding data in CBC mode (PKCS5 Padding)
                padding: block-size - ((len + 1) % block-size)
                insert/dup tail content padding padding + 1
                ;?? padding
            ]
            ;?? content

            ; on next line are 3 ops.. encrypting content, padding and getting the result  
            encrypted: read update write encrypt-port content

            ;-- TLS versions 1.1 and above include the locale-IV in plaintext.
            insert encrypted locale-hs-IV
            ;clear locale-hs-IV ;-- avoid accidental reuse
        ]
        binary/init bin 0 ;reset the bin buffer
        ++ seq-write
    ]
    encrypted
]



decrypt-tls-record: func [
    ;; Decrypts an incoming TLS record, verifies MAC/tag, and produces the plaintext application or handshake data.
    ctx  [object! ] ;; TLS context containing keys, IVs, and protocol state
    data [binary! ] ;; Encrypted TLS record data (without record header)
    type [integer!] ;; TLS record type (22=handshake, 23=application_data, etc.)
    /local
     length         ;; Length of encrypted data
     nonce          ;; AEAD nonce for TLS 1.3 encryption
     seq-bytes      ;; Sequence number in binary format
     mac            ;; Authentication tag/MAC value
     tag            ;; Computed authentication tag for verification\
     aad            ;; Additional data used for AEAD
][
    log-more ["---------------- decrypt-tls-record" type]
    ;?? data
    aad: clear #{}
    with ctx [
        either TLS13? [
            ;-- TLS 1.3 AEAD Decryption --
            ;; Build Additional Authenticated Data (AAD) for AEAD
            ;; AAD = record_type + legacy_version + plaintext_length
            length: length? data
            binary/write aad [
                UI8   :type
                UI16  :legacy-version  
                UI16  :length
            ]
            ; TLS 1.3 nonce: IV XOR sequence number
            nonce: append clear #{} any [remote-ap-IV remote-hs-IV]
            seq-bytes: #{00000000 0000000000000000}
            binary/write seq-bytes [atz 4 ui64be :seq-read]

            ;; XOR the last 8 bytes of IV with sequence number to create nonce
            nonce: nonce xor seq-bytes
            modify decrypt-port 'iv nonce
            ;?? nonce ?? aad ?? seq-read
            ;; Set up AEAD decryption with AAD
            write  decrypt-port :aad    ;; Provide AAD to decrypt port
            ;; Extract authentication tag (last 16 bytes) from ciphertext
            mac:  take/last/part data 16
            ;; Decrypt the ciphertext (without auth tag)
            data: read write decrypt-port data
            ;; Verify authentication tag matches computed tag
            unless equal? mac take decrypt-port [
                log-error "Failed to validate MAC after decryption!"
                cause-TLS-error 'Bad_record_MAC
            ]
            ;; remove possible padding
            trim/tail data
        ][  ;-- TLS 1.2 Decryption --
            ;; Build MAC input for TLS 1.2: sequence + type + version
            binary/write aad [
                UI64  :seq-read        ;; 8-byte sequence number
                UI8   :type            ;; Record type
                UI16  :legacy-version  ;; Protocol version
            ]
            either is-aead? [
                ;; TLS 1.2 AEAD Mode (GCM, CCM, etc.)
                ;; For most AEAD ciphers, extract explicit nonce from record
                if crypt-method <> 'CHACHA20-POLY1305 [
                    ;; Update remote IV with explicit nonce from first 8 bytes
                    change/part skip remote-hs-IV 4 take/part data 8 8
                    modify decrypt-port 'iv remote-hs-IV
                    log-more ["Remote IV:^[[32m" remote-hs-IV]
                ]
                ;; Complete AAD with plaintext length (without auth tag)
                binary/write tail aad reduce ['UI16 (length? data) - 16]
                write decrypt-port aad ; AAD chunk
                log-more ["AAD:      ^[[32m" aad]

                ;; Extract and verify authentication tag
                mac: take/last/part data 16 ; expected mac
                data: read write decrypt-port data
                unless equal? mac tag: take decrypt-port [
                    log-debug "Failed to validate MAC after decryption!"
                    log-debug ["Expected:" mac]
                    log-debug ["Counted: " tag]
                    critical-error: 'Bad_record_MAC
                ]
            ][
                ;; TLS 1.2 CBC Mode with HMAC
                if block-size [
                    ;; Extract initialization vector from beginning of record
                    remote-hs-IV: take/part data block-size
                ]
                ;; Perform block cipher decryption
                modify decrypt-port 'init-vector remote-hs-IV
                data: read update write decrypt-port :data

                if block-size [
                    ;; Handle PKCS#7 padding in CBC mode
                    ;; Padding length is stored in the last byte
                    clear skip tail data (-1 - (to integer! last data))
                    ;; Extract MAC from end of plaintext
                    mac: take/last/part data mac-size
                    ;; Verify HMAC over sequence + type + version + plaintext
                    binary/write tail aad [ UI16BYTES :data ] ;; Append plaintext to MAC input
                    if mac <> checksum/with aad hash-type remote-mac [
                        critical-error: 'Bad_record_MAC
                    ]
                    ;; Clear IV to prevent reuse (TLS 1.1+ requirement)
                    unset 'remote-hs-IV
                ]
            ]
            ;; Clear temporary buffer
            binary/init bin 0
        ]
        ++ seq-read
    ]
    ;; Return none if decryption failed, otherwise return decrypted data
    unless data [ critical-error: 'Bad_record_MAC ]
    data
]


derive-application-traffic-secrets: func [
    ;; Derives post-handshake traffic secrets and verifies the Finished handshake values.
    ctx [object!]    ;; TLS context with handshake state and key material
    /local
     derived-secret  ;; temporary storage for derived intermediate secret
     finished-hash   ;; hash of handshake transcript
     finished-key    ;; key for computing client's finished verify data
][with ctx [
    either TLS13? [
        log-info "Derive application traffic secrets"
        ;; TLS 1.3 path
        ;; Get hash of all handshake messages to this point (Client Hello .. Server Finished)
        finished-hash: get-transcript-hash ctx _
        ;; Derive Finished key from client traffic secret to verify server Finished
        finished-key: HKDF-Expand/label hash-type either server? [remote-hs-secret][locale-hs-secret] #{} mac-size "finished"
        ;; Derive Client Handshake Finished data
        verify-data: checksum/with finished-hash hash-type finished-key
        ;?? verify-data ?? context-messages
        ;; This data should be sent to the server as the last client's message

        ;; We should already have a handshake-secret from key derivation...
        ;; Derive the intermediate secret for master secret calculation
        ;; This follows RFC 8446 key schedule: Derive-Secret(HS, "derived", "")
        derived-secret: HKDF-Expand/label hash-type handshake-secret empty-hash/:hash-type mac-size "derived"
        
        ;; Extract master secret using derived secret as salt and zero key as input
        ;; Master-Secret = HKDF-Extract(Derive-Secret(HS, "derived", ""), 0)
        master-secret: HKDF-Extract      hash-type :derived-secret zero-keys/:hash-type
        log-debug ["Master Secret:^[[1m" master-secret]
        log-debug ["Locale Handshake Secret:^[[1m" locale-hs-secret]
        log-debug ["Remote Handshake Secret:^[[1m" remote-hs-secret]

        ;; Derive application traffic secrets from master secret using finished handshake hash
        ;; These are used for post-handshake application data encryption
        either server? [
            locale-ap-secret: HKDF-Expand/label hash-type master-secret :finished-hash mac-size "s ap traffic"
            remote-ap-secret: HKDF-Expand/label hash-type master-secret :finished-hash mac-size "c ap traffic"
        ][
            locale-ap-secret: HKDF-Expand/label hash-type master-secret :finished-hash mac-size "c ap traffic"
            remote-ap-secret: HKDF-Expand/label hash-type master-secret :finished-hash mac-size "s ap traffic"
        ]
        log-debug ["Locale Traffic   Secret:^[[1m" locale-ap-secret]
        log-debug ["Remote Traffic   Secret:^[[1m" remote-ap-secret]
        reading?: server?
    ][
        ;; TLS 1.2 path: verify_data computed via PRF over master_secret
        verify-data: prf hash-type either server? ["client finished"]["server finished"] :finished-hash master-secret 12
    ]
]]


switch-to-app-keys: func [
    ;; Switches the cryptographic context to application data keys after the handshake is complete.
    ctx [object!]
][with ctx [
    log-info "Switch to application keys for traffic"
    ;; Derive application data keys from traffic secrets (for post-handshake encryption)
    locale-ap-key:  HKDF-Expand/label hash-type locale-ap-secret #{} crypt-size "key"
    remote-ap-key:  HKDF-Expand/label hash-type remote-ap-secret #{} crypt-size "key"
    ;; Derive application data IVs from traffic secrets (total IV size including dynamic part)
    locale-ap-IV:   HKDF-Expand/label hash-type locale-ap-secret #{} IV-size + IV-size-dynamic "iv"
    remote-ap-IV:   HKDF-Expand/label hash-type remote-ap-secret #{} IV-size + IV-size-dynamic "iv"

    log-debug ["Locale App IV :^[[1m" locale-ap-IV ]
    log-debug ["Remote App IV :^[[1m" remote-ap-IV ]
    log-debug ["Locale App Key:^[[1m" locale-ap-key]
    log-debug ["Remote App Key:^[[1m" remote-ap-key]

    ;; Close handshake crypt ports...
    close encrypt-port
    close decrypt-port
    ;; Open application
    encrypt-port: open [
        scheme:      'crypt
        algorithm:   :crypt-method
        init-vector: :locale-ap-IV
        key:         :locale-ap-key
    ]
    decrypt-port: open [
        scheme:      'crypt
        direction:   'decrypt
        algorithm:   :crypt-method
        init-vector: :remote-ap-IV
        key:         :remote-ap-key
    ]
    ;@@ TODO: could be supported in the spec directly, but that is not implemented yet!
    modify encrypt-port 'aad-length :aad-length
    modify decrypt-port 'aad-length :aad-length
    if tag-length > 0 [
        modify decrypt-port 'tag-length :tag-length
        modify encrypt-port 'tag-length :tag-length
    ]
    seq-read: seq-write: 0
]]

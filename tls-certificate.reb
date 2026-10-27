Rebol [
    title: "TLS Certificate Functions"
    file:  %tls-certificate.reb
    license: 'MIT ;= SPDX-License-Identifier
]

;; How to handle failed certificate checks:
;;  'log   - failures are only logged (and collected in ctx/certificate-errors)
;;  'error - failures are TLS errors
;;  none   - certificates are not checked
;; Set using: system/schemes/tls/config [verify: error]
verify-certificates: 'log

certificate-failure: func [
    ;; Reports a failed certificate check (logged, or raised as a TLS error with the given alert).
    ctx   [object!]
    alert [word!]
    msg   [block! string!]
][
    if block? msg [msg: reform msg]
    log-error msg
    append any [ctx/certificate-errors ctx/certificate-errors: copy []] msg
    if verify-certificates = 'error [cause-TLS-error alert]
]

check-certificate-dates: func [
    ;; Checks that the certificate is valid now (or at the given time).
    ctx  [object!]
    cert [object!]
    /at time [date!] "Time of the check (default: now)"
][
    time: any [time now/utc]
    unless all [
        date? cert/valid-from
        date? cert/valid-to
        cert/valid-from <= time
        time <= cert/valid-to
    ][
        certificate-failure ctx 'Certificate_expired [
            "Certificate is not valid at" time "(valid from" cert/valid-from "to" cert/valid-to
            "subject:" mold/flat cert/subject ")"
        ]
    ]
]

decode-certificates: function [
    ;; Parses a TLS CERTIFICATE handshake message and extracts and verifies server certificate(s).
    ctx [object!]
    msg [binary!]
][
    assert-prev-state ctx [SERVER_HELLO CLIENT_HELLO ENCRYPTED_EXTENSIONS]
    msg: binary msg
    if ctx/TLS13? [
        cert-context: binary/read msg 'UI8BYTES
        ;? cert-context
    ]
    len: binary/read msg 'UI24
    if len != length? msg/buffer [
        log-error ["Improper certificate list end?" len "<>" length? msg/buffer]
        cause-TLS-error 'Handshake_failure
    ]
    
    while [3 < length? msg/buffer][
        cert: binary/read msg 'UI24BYTES
        if ctx/TLS13? [
           cert-extensions: binary/read msg 'UI16BYTES
           ;? cert-extensions
        ]
        unless cert: attempt [decode 'CRT cert] [
            log-error "Failed to decode a certificate!"
            cause-TLS-error 'Bad_certificate
        ]
        append ctx/server-certs cert
        log-more ["Certificate subject:^[[1m" mold/only/flat cert/subject]
        if verify-certificates [check-certificate-dates ctx cert]
    ]
    ;log-debug ["Received" length? ctx/server-certs "server certificates."]
    ;? ctx/server-certs
    try/with [
        key: ctx/server-certs/1/public-key
        switch key/1 [
            ecPublicKey [
                ctx/pub-key: key/3
                ctx/pub-exp: key/2      ;curve name
                if 0 == ctx/pub-key/1 [remove ctx/pub-key]
            ]
            rsaEncryption [
                ctx/pub-key: key/2/1
                ctx/pub-exp: key/2/2
            ]
        ]
    ][
        log-error "Missing public key in certifiate"
        cause-TLS-error 'Bad_certificate
    ]
    ;@@TODO: certificate validation
]

encode-certificate-entries: function [
    ;; Encodes DER certificates as a TLS1.3 certificate_list (each CertificateEntry has its own extensions).
    ders [block!]
][
    bin: binary 4000
    foreach der ders [
        binary/write bin [
            UI24BYTES :der
            UI16      0    ;= CertificateEntry extensions (none)
        ]
    ]
    bin/buffer
]

decode-certificate-verify: function [
    ;; Parses and validates a TLS CERTIFICATE_VERIFY handshake message using the corresponding certificate and signature.
    ctx [object!]
    msg [object! binary!]
][
    ;; Because the server is generating ephemeral keys for each session (optional in TLS 1.2,
    ;; mandatory in TLS 1.3) the session is not inherently tied to the certificate as it was
    ;; in previous versions of TLS, when the certificate's public/private key were used for
    ;; key exchange.
    ;;
    ;; To prove that the server owns the server certificate (giving the certificate validity
    ;; in this TLS session), it signs a hash of the handshake messages using the private key
    ;; associated with the certificate. The signature can be proven valid by the client by
    ;; using the public key included in the certificate.
    binary/read msg [
       signature-type: UI16
       signature: UI16BYTES
    ]
    ;@@TODO: certificate validation also for other types!
    log-debug ["Verify certificate using type:^[[1m" *SignatureScheme/name signature-type]
    ;?? signature
    ;?? ctx/context-messages
    if signature-type == 0#0804 [
        either system/version < 3.19.7 [
            ;@@ TEMPORARY FIX!
            log-error "Current Rebol version is not able to validate this certificate!"
        ][
            to-sign: rejoin [
                server-certificate-verify-context
                ;; Get hash of handshake messages (Client Hello .. Certificate)
                get-transcript-hash ctx 'CERTIFICATE
            ]
            key: rsa-init ctx/pub-key ctx/pub-exp
            unless rsa/verify/pss :key :to-sign :signature [
                log-error "Certificate validation failed!"
            ]
        ]
    ]
]

decode-certificate-request: function [
    ;; Decodes a TLS CERTIFICATE_REQUEST handshake message, extracting requested certificate types, signature algorithms, and authorities.
    ctx     [object!]
    message [binary!]
][
    either ctx/TLS13? [
    ;; In TLS 1.3, CertificateRequest is used in two places:
    ;;  During the handshake if the server wishes to authenticate the client (structure changed: includes a certificate_request_context and possibly extensions).
    ;;  After the handshake (post-handshake authentication), the server can request a client certificate at any time.
    ;; https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
    ;@@TODO: Not implemented!
    ][
    ;; In TLS 1.2 and earlier, CertificateRequest is sent by the server if it wants the client to authenticate itself
    ;; with a certificate. This is sent during the handshake after ServerHello, Certificate, ServerKeyExchange, and
    ;; before ServerHelloDone. The client then responds with its certificate (if available), or none,
    ;; followed by CertificateVerify, etc..
    ;; https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.4
        assert-prev-state ctx [SERVER_HELLO SERVER_KEY_EXCHANGE CERTIFICATE]
        binary/read message [
            certificate_types:              UI8BYTES
            supported_signature_algorithms: UI16BYTES
            certificate_authorities:        BYTES
        ]
    ]
    log-more ["R[" ctx/seq-read "] certificate_types:   " certificate_types]
    log-more ["R[" ctx/seq-read "] signature_algorithms:" supported_signature_algorithms]
    log-more ["R[" ctx/seq-read "] certifi_authorities: " certificate_authorities]
    ;@@ For now this message is not handled!
]

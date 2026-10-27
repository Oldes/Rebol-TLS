Rebol [
	title: "Rebol/TLS offline unit tests"
]

;;=============================================================================
;; Minimal self-contained harness
;;=============================================================================

test-count: 0
fail-count: 0
skip-count: 0
failed: copy []

group: func ["Starts a named group of tests" name [string!]][
	print ajoin [lf as-yellow "== " as-yellow name]
]

;; NOTE: plain `func` with explicit locals - `function` would collect the
;; counter set-words as locals and the totals would never move.
;;
;; A test block must EVALUATE to true; anything else counts as a failure and
;; is printed as the detail, so a check can hand back a string saying what
;; went wrong. Never use `return` inside one - it would return from
;; `--test--` itself and the result would never be counted.
--test--: func [
	"Passes when the code block evaluates to true"
	name [string!]
	code [block!]
	/local result
][
	test-count: test-count + 1
	result: try code
	case [
		error? :result [
			fail-count: fail-count + 1
			append failed name
			print [as-red "[FAIL]" name]
			print [as-red "      " mold/flat :result]
		]
		:result = true [
			print [as-green "[ ok ]" name]
		]
		true [
			fail-count: fail-count + 1
			append failed name
			print [as-red "[FAIL]" name "=>" mold/flat/part :result 60]
		]
	]
	:result
]

--skip--: func ["Counts a test which cannot run here" name [string!]][
	skip-count: skip-count + 1
	print [as-purple "[skip]" name]
]

;; Compares a result with what it should be and hands back the actual value
;; when they differ, so the failure line shows it.
is?: func ["Compares a value with the expected one" value expected][
	any [value == expected  ajoin ["got " mold/flat/part value 60]]
]

summary: does [
	print ajoin [lf as-yellow "-----------------------------------------------------------------------------"]
	print [
		"tests:" test-count
		as-green ajoin ["passed: " test-count - fail-count - skip-count]
		either fail-count > 0 [as-red ajoin ["failed: " fail-count]][ajoin ["failed: " fail-count]]
		as-purple ajoin ["skipped: " skip-count]
	]
	if fail-count > 0 [
		print as-red ajoin ["^/Failed tests:^/  " mold/flat failed]
	]
	print ""
	quit/return either fail-count > 0 [1][0]
]

;;=============================================================================
;; Setup: load the TLS sources in the same order as `tls.reb` includes them
;;=============================================================================

print-horizontal-line: :print-hline
unset in system/schemes 'tls
do %build/prot-tls.reb

;; Counts non-overlapping occurrences of a pattern in a series
count-of: func ["Counts occurrences of a value in a series" series pattern /local n][
	n: 0
	while [series: find/tail series pattern][n: n + 1]
	n
]

;;=============================================================================

group "prepare-server-hello"

--test-- "extensions are not accumulated across calls" [
	ctx: new-TLS-context [
		server?:      true
		session-id:   #{}
		cipher-suite: 0#C02F ;= TLS_ECDHE_RSA_WITH_AES-128-GCM_SHA256 (TLS1.2 path)
		extensions:   #[renegotiation_info: #{00}]
	]
	prepare-server-hello ctx
	prepare-server-hello ctx
	;; renegotiation_info must be in the second ServerHello exactly once
	is? count-of head ctx/out/buffer #{FF01000100} 1
]


;; Returns names of extensions sent in the ServerHello record in the output buffer
server-hello-extensions: func [
	"Decodes extensions of the ServerHello record"
	ctx [object!]
	/local data
][
	data: binary/read binary head ctx/out/buffer [
		UI8 UI16 UI16 ;= record header
		UI8 UI24      ;= handshake header
		UI16 BYTES 32 UI8BYTES UI16 UI8
		UI16BYTES     ;= extensions
	]
	decode-extensions new-TLS-context [] last data
]

client-key: ecdh/public ecdh/init none 'curve25519

--test-- "TLS1.2 echoes point formats and renegotiation info" [
	ctx: new-TLS-context [
		server?:      true
		session-id:   #{}
		cipher-suite: 0#C02F
		extensions:   #[supported_point_formats: #{03000102} renegotiation_info: #{00}]
	]
	prepare-server-hello ctx
	is? sort words-of server-hello-extensions ctx [renegotiation_info supported_point_formats]
]

--test-- "TLS1.3 sends only supported_versions and key_share" [
	ctx: new-TLS-context [
		server?:      true
		session-id:   #{}
		cipher-suite: 0#1301
		extensions:   compose/deep #[
			supported_versions:      [0#0304 0#0303]
			key_share:               [curve25519 (client-key)]
			supported_point_formats: #{03000102}
			renegotiation_info:      #{00}
		]
	]
	prepare-server-hello ctx
	is? sort words-of server-hello-extensions ctx [key_share supported_versions]
]

--test-- "HelloRetryRequest asks for a group supported by the client" [
	ctx: new-TLS-context [
		server?:          true
		session-id:       #{}
		cipher-suite:     0#1301
		hash-type:        'SHA256
		context-messages: reduce ['CLIENT_HELLO #{01000000}]
		extensions:       #[
			supported_versions: [0#0304 0#0303]
			supported_groups:   [secp192r1 secp256r1] ;= server does not use secp192r1
			key_share:          [secp192r1 #{04}]
		]
	]
	prepare-server-hello ctx
	is? select server-hello-extensions ctx 'key_share 0#0017 ;= secp256r1
]

--test-- "HelloRetryRequest without a common group fails" [
	ctx: new-TLS-context [
		server?:      true
		session-id:   #{}
		cipher-suite: 0#1301
		extensions:   #[
			supported_versions: [0#0304 0#0303]
			supported_groups:   [secp192r1]
			key_share:          [secp192r1 #{04}]
		]
	]
	e: try [prepare-server-hello ctx]
	all [error? e  did find form e "Insufficient security"]
]

--test-- "HelloRetryRequest replaces ClientHello1 in transcript with message_hash" [
	ch1: #{0100000401020304} ;= fake ClientHello1
	ctx: new-TLS-context [
		server?:          true
		session-id:       #{}
		cipher-suite:     0#1301
		hash-type:        'SHA256
		state:            'CLIENT_HELLO
		context-messages: reduce ['CLIENT_HELLO copy ch1]
		extensions:       #[
			supported_versions: [0#0304 0#0303]
			supported_groups:   [secp192r1 secp256r1]
			key_share:          [secp192r1 #{04}]
		]
	]
	prepare-server-hello ctx
	is? ctx/context-messages/2 join #{FE000020} checksum ch1 'sha256
]


group "TLS1.3 record protection"

;; Returns client and server contexts with derived TLS1.3 handshake keys
;; (the state right after both sides processed ServerHello)
handshake-pair: func [
	"Makes a TLS1.3 client/server context pair with matching handshake keys"
	/local pair transcript ctx
][
	transcript: [CLIENT_HELLO #{0100000401020304} SERVER_HELLO #{0200000405060708}]
	pair: copy []
	foreach server? [#(false) #(true)][
		ctx: new-TLS-context [
			TLS13?:           true
			version:          0#0304
			cipher-suite:     0#1301 ;= TLS_AES_128_GCM_SHA256
			context-messages: copy/deep transcript
		]
		ctx/server?: server?
		TLS-init-cipher-suite ctx
		ctx/pre-secret: #{000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}
		TLS-key-expansion ctx
		append pair ctx
	]
	pair
]

--test-- "server decrypts client Finished after deriving application secrets" [
	set [client server] handshake-pair
	;; server derives application secrets right after sending its Finished
	derive-application-traffic-secrets server
	msg: #{1400000401020304}
	record: wrap-record client msg 22
	is? decrypt-tls-record server record 23 join msg #{16}
]

--test-- "application data after switching to application keys" [
	set [client server] handshake-pair
	derive-application-traffic-secrets server
	record: wrap-record client #{1400000401020304} 22  ;= client Finished
	decrypt-tls-record server record 23
	derive-application-traffic-secrets client           ;= client switches decrypt
	switch-to-app-encrypt client                        ;= in prepare-finished-message
	switch-to-app-decrypt server                        ;= after client Finished
	msg: to binary! "GET / HTTP/1.1"
	record: wrap-record client msg 23
	is? decrypt-tls-record server record 23 join msg #{17}
]



group "TLS-context"

--test-- "connections do not share I/O buffers" [
	spec: [server?: true session-id: #{} cipher-suite: 0#C02F extensions: #[]]
	a: new-TLS-context spec
	b: new-TLS-context spec
	prepare-server-hello a
	hello: copy head a/out/buffer
	prepare-server-hello b
	is? head a/out/buffer hello
]


group "TLS1.2 record protection"

;; Returns client and server contexts with matching TLS1.2 keys
;; (the state right after the key exchange)
tls12-pair: func [
	"Makes a TLS1.2 client/server context pair with matching keys"
	/local pair ctx
][
	pair: copy []
	foreach server? [#(false) #(true)][
		ctx: new-TLS-context [
			version:      0#0303
			cipher-suite: 0#C02F ;= TLS_ECDHE_RSA_WITH_AES-128-GCM_SHA256
			pre-secret:   #{000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}
		]
		ctx/server?: server?
		ctx/locale-random: either server? [#{AA}][#{CC}]
		ctx/remote-random: either server? [#{CC}][#{AA}]
		TLS-init-cipher-suite ctx
		TLS-key-expansion ctx
		append pair ctx
	]
	pair
]

--test-- "TLS1.2 application data records are numbered sequentially" [
	set [client server] tls12-pair
	prepare-application-data client "first"
	prepare-application-data client "second"
	records: binary/read binary head client/out/buffer [
		UI8 UI16 UI16BYTES
		UI8 UI16 UI16BYTES
	]
	result: reduce [
		to string! decrypt-tls-record server records/3 23
		to string! decrypt-tls-record server records/6 23
	]
	all [
		none? server/critical-error
		is? result ["first" "second"]
	]
]


group "TLS1.2 ServerKeyExchange"

;; Returns a TLS1.2 client context (after receiving Certificate) and
;; an ECDHE_ECDSA ServerKeyExchange message signed by the server's key
ecdsa-key-exchange: func [
	"Makes a client context and a signed ServerKeyExchange message"
	/local ctx cert-key params signature
][
	ctx: new-TLS-context [
		key-method:    'ECDHE_ECDSA
		state-prev:    'CERTIFICATE
		locale-random: #{CC}
		remote-random: #{AA}
		server-certs:  reduce [object [public-key: none]]
		pub-exp:       'secp256r1
	]
	;; server's ECDHE parameters (curve type, named curve, public key)
	params: binary/write make binary! 200 compose [
		UI8 3  UI16 0#0017  UI8BYTES (ecdh/public ecdh/init none 'secp256r1)
	]
	;; signed using the certificate's key
	cert-key: ecdh/init none 'secp256r1
	signature: ecdsa/sign cert-key checksum rejoin [#{CC} #{AA} params/buffer] 'sha256
	ctx/pub-key: ecdh/public cert-key ;= as in the certificate
	reduce [
		ctx
		binary/write params [UI8 4 UI8 3 UI16BYTES :signature] ;= sha256 + ecdsa
	]
]

--test-- "ECDSA signed ServerKeyExchange is accepted" [
	set [ctx msg] ecdsa-key-exchange
	decode-server-key-exchange ctx msg/buffer
	binary? ctx/pre-secret
]

--test-- "ServerKeyExchange with invalid ECDSA signature is refused" [
	set [ctx msg] ecdsa-key-exchange
	msg: head msg/buffer
	change back tail msg 255 - last msg ;= damage the signature
	e: try [decode-server-key-exchange ctx msg]
	all [error? e  did find form e "Decode error"]
]

--test-- "ServerKeyExchange with extra bytes is refused" [
	set [ctx msg] ecdsa-key-exchange
	msg: append head msg/buffer #{00}
	e: try [decode-server-key-exchange ctx msg]
	all [error? e  did find form e "Decode error"]
]



group "Certificates"

der: select decode 'pkix read %certs/MyCertificate.crt 'binary

--test-- "each certificate entry has its own extensions" [
	is? encode-certificate-entries [#{AA} #{BBBB}] #{000001AA0000000002BBBB0000}
]

--test-- "client decodes certificate chain sent by server" [
	entries: encode-certificate-entries reduce [der der]
	ctx: new-TLS-context [TLS13?: true state-prev: 'ENCRYPTED_EXTENSIONS]
	;; Certificate message body (as in prepare-server-certificate)
	msg: binary/write make binary! 5000 [UI8 0 UI24BYTES :entries]
	decode-certificates ctx msg/buffer
	is? length? ctx/server-certs 2
]

summary

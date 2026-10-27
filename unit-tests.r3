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

unset in system/schemes 'tls
tls: do %build/prot-tls.reb
;; make the module's internal functions visible to the tests
resolve/extend/all system/contexts/user tls

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
	/suite "Use other cipher suite (default: TLS_ECDHE_RSA_WITH_AES-128-GCM_SHA256)"
	 id [integer!]
	/local pair ctx
][
	pair: copy []
	foreach server? [#(false) #(true)][
		ctx: new-TLS-context [
			version:      0#0303
			pre-secret:   #{000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}
		]
		ctx/cipher-suite: any [id 0#C02F]
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
	is? reduce [server/critical-error result] [#(none) ["first" "second"]]
]

--test-- "TLS1.2 CBC record is decrypted" [
	set [client server] tls12-pair/suite 0#C027 ;= TLS_ECDHE_RSA_WITH_AES-128-CBC_SHA256
	prepare-application-data client "hello"
	record: binary/read binary head client/out/buffer [UI8 UI16 UI16BYTES]
	result: decrypt-tls-record server record/3 23
	is? reduce [server/critical-error result] [#(none) #{68656C6C6F}]
]

--test-- "TLS1.2 CBC record with invalid padding bytes is refused" [
	set [client server] tls12-pair/suite 0#C027
	content: to binary! "hello"
	;; MAC over: seq_num type version length content
	mac: checksum/with rejoin [#{0000000000000000 17 0303 0005} content] 'sha256 client/locale-mac
	data: rejoin [content mac]                     ;= 37 bytes
	append/dup data 10 11                          ;= padding to 48 bytes (11 bytes of value 10)
	change at data 38 #{00}                        ;= damage the first padding byte (last one is still valid)
	iv: #{000102030405060708090A0B0C0D0E0F}
	modify client/encrypt-port 'init-vector iv
	record: join iv read update write client/encrypt-port data
	decrypt-tls-record server record 23
	is? server/critical-error = 'Bad_record_MAC true
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

--test-- "certificate which cannot be decoded is refused" [
	entries: encode-certificate-entries [#{0102030405}] ;= `decode 'CRT` fails on it
	ctx: new-TLS-context [TLS13?: true state-prev: 'ENCRYPTED_EXTENSIONS]
	msg: binary/write make binary! 100 [UI8 0 UI24BYTES :entries]
	tls-verbosity 2 ;= the error was raised only with logging enabled
	e: try [decode-certificates ctx msg/buffer]
	tls-verbosity 0
	all [error? e  did find form e "Bad certificate"]
]



group "do-TLS-write"

;; A port which only collects written data (used instead of the TCP port)
sys/make-scheme [
	name:  'test-sink
	title: "Collects written data"
	actor: [
		open:  func [port][port/data: make binary! 40000 port]
		write: func [port data][append port/data data port]
	]
]

--test-- "multibyte string is split to records of max 16KiB" [
	set [client server] handshake-pair
	derive-application-traffic-secrets server
	derive-application-traffic-secrets client
	switch-to-app-encrypt client
	switch-to-app-decrypt server
	client/protocol: 'APPLICATION
	client/tcp-port: open test-sink://
	port: make port! [scheme: 'tls]
	port/extra: client
	text: append/dup copy "" #"ž" 10000 ;= 20000 bytes in UTF-8
	do-TLS-write port text
	;; decrypt all written records
	data: make binary! 20000
	sizes: copy []
	bin: binary client/tcp-port/data
	while [not tail? bin/buffer][
		record: binary/read bin [UI8 UI16 UI16BYTES]
		plain: decrypt-tls-record server record/3 23
		take/last plain ;= inner content type
		append sizes length? plain
		append data plain
	]
	is? reduce [sizes  data == to binary! text] [[16384 3616] #(true)]
]



group "decrypt-tls-record"

;; A crypt-like port which never returns any data
sys/make-scheme [
	name:  'test-null
	title: "Returns no data"
	actor: [
		open:   func [port][port]
		write:  func [port data][port]
		read:   func [port][none]
		modify: func [port field value][true]
		take:   func [port][none]
	]
]

--test-- "failed decryption is reported in the context, not globally" [
	unset 'critical-error
	ctx: new-TLS-context [
		crypt-method: 'AES-128-GCM
		is-aead?:     true
		remote-hs-IV: #{000000000000000000000000}
		decrypt-port: open test-null://
	]
	data: decrypt-tls-record ctx append/dup copy #{} 0 40 23
	is? reduce [data ctx/critical-error value? 'critical-error] [#(none) Bad_record_MAC #(false)]
]



group "TLS-init-cipher-suite"

--test-- "unknown cipher suite is refused without error" [
	ctx: new-TLS-context [cipher-suite: 0#009F] ;= TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (not in *Cipher-suite)
	is? TLS-init-cipher-suite ctx false
]

--test-- "client advertises only cipher suites it can use" [
	bad: copy []
	bin: binary suported-cipher-suites-binary
	while [not tail? bin/buffer][
		id: binary/read bin 'UI16
		unless id == 0#00FF [ ;= TLS_EMPTY_RENEGOTIATION_INFO_SCSV
			ctx: new-TLS-context [cipher-suite: id]
			unless TLS-init-cipher-suite ctx [append bad skip to binary! id 6]
		]
	]
	is? bad []
]



group "decode-client-hello"

;; Returns ClientHello message body offering TLS1.3 or only TLS1.2
client-hello: func [
	"Makes a ClientHello message body"
	tls13? [logic!]
	/suites "Offered cipher suites (default: TLS_AES_128_GCM_SHA256 and a TLS1.2 one)"
	 list [binary!]
	/local ext key bin
][
	ext: make binary! 100
	key: ecdh/public ecdh/init none 'curve25519
	binary/write ext [UI16 10  UI16 4  UI16 2  UI16 0#001D] ;= supported_groups: curve25519
	if tls13? [
		binary/write tail ext compose [
			UI16 43  UI16 3  UI8 2  UI16 0#0304                   ;= supported_versions: TLS1.3
			UI16 51  UI16 (6 + length? key)  UI16 (4 + length? key) ;= key_share
			UI16 0#001D  UI16BYTES :key
		]
	]
	bin: binary/write make binary! 200 compose [
		UI16      0#0303
		BYTES     #{0000000000000000000000000000000000000000000000000000000000000000}
		UI8BYTES  #{}
		UI16BYTES (any [list #{1301C02F}])
		UI8BYTES  #{00}
		UI16BYTES :ext
	]
	head bin/buffer
]

--test-- "server accepts ClientHello offering TLS1.3" [
	ctx: new-TLS-context [server?: true]
	decode-client-hello ctx client-hello true
	is? select ctx/extensions 'supported_versions [0#0304]
]

--test-- "server refuses ClientHello without TLS1.3" [
	ctx: new-TLS-context [server?: true]
	e: try [decode-client-hello ctx client-hello false]
	all [error? e  did find form e "Protocol version"]
]

--test-- "server chooses TLS1.3 cipher suite for TLS1.3 session" [
	ctx: new-TLS-context [server?: true]
	decode-client-hello ctx client-hello/suites true #{C02F1301} ;= TLS1.2 suite preferred by client
	is? ctx/cipher-suite 0#1301
]

--test-- "TLS1.3 ClientHello without TLS1.3 cipher suite is refused" [
	ctx: new-TLS-context [server?: true]
	e: try [decode-client-hello ctx client-hello/suites true #{C02F}]
	all [error? e  did find form e "Handshake failure"]
]



group "Sources"

--test-- "sources contain no debug prints" [
	bad: copy []
	foreach file read %./ [
		if all [find/match file "tls" %.reb = suffix? file][
			;; `load` drops comments, so only active code is checked
			if find mold load file "?? " [append bad file]
		]
	]
	is? bad []
]



group "TLS server (loopback)"

;; A minimal HTTP-like application using the TLS server port like a TCP server port
server: open [
	scheme: 'tls
	port:   18436
	config: [certificates: %certs/MyCertificate.crt private-key: %certs/MyKey.key]
]
server-events: copy []
close-on-wrote?: true
client-info: none
use-mode?: false
server/awake: func [event [event!] /local client][
	append server-events event/type
	if event/type = 'accept [
		client: first event/port
		client-info: attempt either use-mode? [
			[query/mode client [remote-ip: local-port:]]
		][	[query client [remote-ip: local-port:]] ]
		client/awake: func [event [event!] /local port][
			port: event/port
			switch event/type [
				read [
					either find port/data #{0D0A0D0A} [
						write port "HTTP/1.1 200 OK^M^/Content-Length: 5^M^/Connection: close^M^/^M^/Hello"
					][	read port ]
				]
				wrote [either close-on-wrote? [close port][read port]] ;= keep-alive like
				close [append server-events 'client-close  close port]
			]
			false
		]
		read client
	]
	false
]

--test-- "client reads response from the TLS server" [
	is? attempt [to string! read https://localhost:18436/] "Hello"
]

--test-- "query on the server port and on the client connection" [
	is? reduce [
		attempt [query server 'local-port]
		client-info
	] [18436 [remote-ip: 127.0.0.1 local-port: 18436]]
]

--test-- "query/mode (deprecated) on the client connection" [
	client-info: none
	use-mode?: true
	attempt [read https://localhost:18436/]
	use-mode?: false
	is? client-info [remote-ip: 127.0.0.1 local-port: 18436]
]

--test-- "server handles next connection; clients don't send events to the server port" [
	clear server-events
	is? reduce [
		attempt [to string! read https://localhost:18436/]
		server-events
	] ["Hello" [accept]]
]

--test-- "connection closed by the client is reported to the application, not to the server" [
	clear server-events
	close-on-wrote?: false
	result: attempt [to string! read https://localhost:18436/]
	wait 0.5 ;= let the server process client's close
	close-on-wrote?: true
	is? reduce [result server-events] ["Hello" [accept client-close]]
]

--test-- "loopback handshake passes all certificate checks with `verify: error`" [
	tls-config [verify: error]
	result: attempt [to string! read https://localhost:18436/]
	tls-config [verify: log]
	is? result "Hello"
]

--test-- "closing the server port stops listening" [
	close server
	is? reduce [
		open? server
		error? try [read https://localhost:18436/]
	] [#(false) #(true)]
]

--test-- "data received with client's FINISHED are reported on the first read" [
	events: copy []
	app: make port! [scheme: 'test-sink]
	app/awake: func [event [event!]][append events reduce [event/type copy event/port/data] true]
	ctx: new-TLS-context [server?: true unread?: true]
	append ctx/port-data "GET / HTTP/1.1^M^/^M^/"
	port: make port! [scheme: 'tls]
	port/extra: ctx
	port/parent: app ;= events are delivered to the parent's awake
	do-TLS-read port
	is? reduce [events ctx/unread?] reduce [reduce ['read to binary! "GET / HTTP/1.1^M^/^M^/"] false]
]



group "prepare-client-hello"

;; Returns names of extensions sent in ClientHello to the given host
client-hello-extensions: func [
	"Prepares ClientHello and returns its extensions"
	host [string! tuple!]
	/local ctx data
][
	ctx: new-TLS-context [tcp-port: make port! [scheme: 'tcp host: none port: 443]]
	ctx/tcp-port/spec/host: host
	TLS-init-context ctx
	prepare-client-hello ctx
	data: binary/read binary head ctx/out/buffer [
		UI8 UI16 UI16 UI8 UI24 ;= record and handshake header
		UI16 BYTES 32 UI8BYTES UI16BYTES UI8BYTES
		UI16BYTES              ;= extensions
	]
	words-of decode-extensions new-TLS-context [server?: true] last data
]

--test-- "server_name is sent for a host name" [
	did find client-hello-extensions "localhost" 'server_name
]

--test-- "server_name is not sent for an IP address" [
	is? collect [
		foreach host ["127.0.0.1" "[::1]" 127.0.0.1][
			if find client-hello-extensions host 'server_name [keep host]
		]
	] []
]

--test-- "transcript contains exactly the ClientHello handshake message" [
	ctx: new-TLS-context [tcp-port: make port! [scheme: 'tcp host: "localhost" port: 443]]
	TLS-init-context ctx
	prepare-client-hello ctx
	is? ctx/context-messages reduce ['CLIENT_HELLO  skip head ctx/out/buffer 5] ;= without the record header
]



group "Alerts"

--test-- "TLS1.3 close_notify alert is decrypted by the peer" [
	set [client server] handshake-pair
	derive-application-traffic-secrets server
	derive-application-traffic-secrets client
	switch-to-app-encrypt client
	switch-to-app-decrypt server
	prepare-alert-close-notify client
	record: binary/read binary head client/out/buffer [UI8 UI16 UI16BYTES]
	is? reduce [
		record/1                                ;= outer type is always application_data
		decrypt-tls-record server record/3 23   ;= alert and inner content type (21)
	] [23 #{010015}]
]

--test-- "TLS1.2 close_notify alert is decrypted by the peer" [
	set [client server] tls12-pair
	prepare-alert-close-notify client
	record: binary/read binary head client/out/buffer [UI8 UI16 UI16BYTES]
	is? reduce [
		record/1
		decrypt-tls-record server record/3 21
		server/critical-error
	] [21 #{0100} #(none)]
]



group "decode-server-hello"

;; Returns a client context in the state after sending ClientHello with a curve25519 key share
client-after-hello: func ["Makes a client context waiting for ServerHello" /local ctx][
	ctx: new-TLS-context [
		version:          0#0303
		state-prev:       'CLIENT_HELLO
		ecdh-group:       'curve25519
		context-messages: reduce ['CLIENT_HELLO #{01000000}]
	]
	ctx/dh-key: ecdh/init none 'curve25519
	ctx
]
;; Returns a TLS1.3 ServerHello message body with the given key_share extension data
server-hello-msg: func [
	"Makes a TLS1.3 ServerHello (or HelloRetryRequest) message body"
	key-share [binary! none!] "key_share extension data (none = no key_share)"
	/hrr "HelloRetryRequest"
	/local ext bin
][
	ext: make binary! 100
	binary/write ext [UI16 43 UI16 2 UI16 0#0304] ;= supported_versions: TLS1.3
	if key-share [binary/write tail ext [UI16 51 UI16BYTES :key-share]]
	bin: binary/write make binary! 200 compose [
		UI16      0#0303
		BYTES     (either hrr [HRR-magic][#{0101010101010101010101010101010101010101010101010101010101010101}])
		UI8BYTES  #{}
		UI16      0#1301
		UI8       0
		UI16BYTES :ext
	]
	head bin/buffer
]
;; key_share extension data with server's public key
key-share-of: func ["Makes key_share data" curve [word!] /local key data][
	key: ecdh/public ecdh/init none curve
	binary/write data: make binary! 100 [UI16 :*EllipticCurves/:curve  UI16BYTES :key]
	data
]

--test-- "TLS1.3 ServerHello with matching key_share is accepted" [
	ctx: client-after-hello
	decode-server-hello ctx server-hello-msg key-share-of 'curve25519
	is? ctx/TLS13? true
]

--test-- "TLS1.3 ServerHello without key_share is refused" [
	e: try [decode-server-hello client-after-hello server-hello-msg none]
	all [error? e  did find form e "Illegal parameter"]
]

--test-- "TLS1.3 ServerHello with key_share for other group is refused" [
	e: try [decode-server-hello client-after-hello server-hello-msg key-share-of 'secp256r1]
	all [error? e  did find form e "Illegal parameter"]
]

--test-- "HelloRetryRequest for the already sent group is refused" [
	e: try [decode-server-hello client-after-hello server-hello-msg/hrr #{001D}] ;= curve25519
	all [error? e  did find form e "Illegal parameter"]
]

--test-- "HelloRetryRequest for other supported group is accepted" [
	ctx: client-after-hello
	decode-server-hello ctx server-hello-msg/hrr #{0017} ;= secp256r1
	is? ctx/extensions/key_share 0#0017
]

;; Returns a TLS1.2 ServerHello message body (without supported_versions) with the given random
tls12-server-hello-msg: func ["Makes a TLS1.2 ServerHello message body" random [binary!] /local bin][
	bin: binary/write make binary! 100 [
		UI16      0#0303
		BYTES     :random
		UI8BYTES  #{}
		UI16      0#C02F ;= TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		UI8       0
		UI16BYTES #{}
	]
	head bin/buffer
]
random-with-end: func ["Makes server random ending with given bytes" tail-bytes [binary!]][
	append append/dup copy #{} 1 32 - length? tail-bytes tail-bytes
]

--test-- "TLS1.2 ServerHello is accepted" [
	ctx: client-after-hello
	decode-server-hello ctx tls12-server-hello-msg random-with-end #{0102030405060708}
	is? reduce [ctx/TLS13? ctx/critical-error] [#(none) #(none)]
]

--test-- "TLS1.2 ServerHello with TLS1.3 downgrade sentinel is refused" [
	bad: copy []
	foreach sentinel [#{444F574E47524401} #{444F574E47524400}][ ;= "DOWNGRD" + 01 (TLS1.2) or 00 (TLS1.1 and older)
		e: try [decode-server-hello client-after-hello tls12-server-hello-msg random-with-end sentinel]
		unless all [error? e  find form e "Illegal parameter"][append bad sentinel]
	]
	is? bad []
]



group "Certificate validation"

;; Returns a client context after decoding Certificate message with given certificates
;; (with the given `verify` setting)
decode-certs-with: func [
	"Decodes certificates using given verify mode"
	mode
	ders [block!]
	/host "Connection to the given host"
	 name [string!]
	/local ctx entries msg
][
	tls-config compose [verify: (mode)]
	entries: encode-certificate-entries ders
	ctx: new-TLS-context [TLS13?: true state-prev: 'ENCRYPTED_EXTENSIONS]
	if host [ctx/tcp-port: make port! [scheme: 'tcp host: none port: 443] ctx/tcp-port/spec/host: name]
	msg: binary/write make binary! 5000 [UI8 0 UI24BYTES :entries]
	decode-certificates ctx msg/buffer
	ctx
]
expired-der: select decode 'pkix read %certs/Expired.crt 'binary ;= valid only until 14-Feb-2023

--test-- "certificate validity is checked at the given time" [
	cert: object [valid-from: 1-Jan-2020/0:00 valid-to: 1-Jan-2120/0:00 subject: [commonName: "test"]]
	ctx: new-TLS-context []
	tls-config [verify: log]
	check-certificate-dates/at ctx cert 1-Jan-2030/0:00
	ok?: none? ctx/certificate-errors
	check-certificate-dates/at ctx cert 1-Jan-2121/0:00
	check-certificate-dates/at ctx cert 1-Jan-2019/0:00
	is? reduce [ok? length? ctx/certificate-errors] [#(true) 2]
]

--test-- "expired certificate is only logged by default" [
	tls-config [verify: log]
	ctx: decode-certs-with 'log reduce [expired-der]
	is? reduce [length? ctx/server-certs  length? ctx/certificate-errors] [1 1]
]

--test-- "expired certificate is refused with `verify: error`" [
	e: try [decode-certs-with 'error reduce [expired-der]]
	tls-config [verify: log]
	all [error? e  did find form e "Certificate expired"]
]

--test-- "valid test certificate passes the checks" [
	ctx: decode-certs-with 'error reduce [der] ;= certs/MyCertificate.crt (valid until 31-Dec-2049)
	tls-config [verify: log]
	is? ctx/certificate-errors none
]

--test-- "host name matching" [
	bad: copy []
	foreach [host name expected] [
		"localhost"       "localhost"       #(true)
		"LocalHost"       "localhost"       #(true)  ;= case-insensitive
		"a.example.com"   "*.example.com"   #(true)
		"example.com"     "*.example.com"   #(false) ;= wildcard needs one label
		"a.b.example.com" "*.example.com"   #(false) ;= ... and only one
		".example.com"    "*.example.com"   #(false)
		"a.example.com"   "a*.example.com"  #(false) ;= only whole left-most label wildcard
		"example.com"     "example.org"     #(false)
	][
		unless expected == host-matches? host name [append bad reduce [host name]]
	]
	is? bad []
]

--test-- "subjectAltName names are used (not commonName), trailing dot ignored" [
	cert: object [subject: [commonName: "other.com"] extensions: [subjectAltName [#(false) ["www.example.com" "*.example.org"]]]]
	ctx: new-TLS-context []
	tls-config [verify: log]
	foreach host ["www.example.com" "a.example.org" "www.example.com."][check-certificate-host ctx cert host]
	ok?: none? ctx/certificate-errors
	check-certificate-host ctx cert "other.com"
	is? reduce [ok? length? ctx/certificate-errors] [#(true) 1]
]

--test-- "commonName is used, when there is no subjectAltName" [
	cert: object [subject: [commonName: "example.com"] extensions: none]
	ctx: new-TLS-context []
	check-certificate-host ctx cert "example.com"
	ok?: none? ctx/certificate-errors
	check-certificate-host ctx cert "www.example.com"
	is? reduce [ok? length? ctx/certificate-errors] [#(true) 1]
]

--test-- "certificate for other host is refused with `verify: error`" [
	ctx: decode-certs-with/host 'error reduce [der] "localhost" ;= certs/MyCertificate.crt is for localhost
	ok?: none? ctx/certificate-errors
	e: try [decode-certs-with/host 'error reduce [der] "example.com"]
	tls-config [verify: log]
	is? reduce [ok?  did all [error? e  find form e "Bad certificate"]] [#(true) #(true)]
]

--test-- "certificate checks are skipped with `verify: none`" [
	ctx: decode-certs-with 'none reduce [expired-der]
	tls-config [verify: log]
	is? ctx/certificate-errors none
]

;; Returns a client context after receiving server's certificate (certs/MyCertificate.crt)
cv-ctx: func ["Makes a client context waiting for CertificateVerify" /local ctx][
	ctx: decode-certs-with 'log reduce [der]
	ctx/hash-type: 'SHA256
	ctx/context-messages: copy/deep reduce ['CLIENT_HELLO #{01000000} 'SERVER_HELLO #{02000000} 'CERTIFICATE #{0B000000}]
	ctx
]
;; Data signed in CertificateVerify
cv-to-sign: func ["Returns data signed in CertificateVerify" ctx [object!]][
	rejoin [server-certificate-verify-context get-transcript-hash ctx 'CERTIFICATE]
]
;; CertificateVerify message body
cv-msg: func ["Makes CertificateVerify message body" scheme [integer!] signature [binary!] /local bin][
	bin: binary/write make binary! 600 [UI16 :scheme UI16BYTES :signature]
	head bin/buffer
]
rsa-private: load %certs/MyKey.key

--test-- "valid RSA-PSS CertificateVerify is accepted" [
	ctx: cv-ctx
	tls-config [verify: error]
	e: try [decode-certificate-verify ctx cv-msg 0#0804 rsa/sign/pss rsa-private cv-to-sign ctx]
	tls-config [verify: log]
	is? reduce [error? e ctx/certificate-errors] [#(false) #(none)]
]

--test-- "invalid RSA-PSS CertificateVerify is refused with `verify: error`" [
	ctx: cv-ctx
	signature: rsa/sign/pss rsa-private cv-to-sign ctx
	append last ctx/context-messages #{00} ;= signature is not for this transcript
	tls-config [verify: error]
	e: try [decode-certificate-verify ctx cv-msg 0#0804 signature]
	tls-config [verify: log]
	did all [error? e  find form e "Decrypt error"]
]

--test-- "invalid CertificateVerify is reported by default" [
	ctx: cv-ctx
	decode-certificate-verify ctx cv-msg 0#0804 #{0102030405}
	is? length? ctx/certificate-errors 1
]

--test-- "ECDSA CertificateVerify is verified" [
	ctx: cv-ctx
	key: ecdh/init none 'secp256r1
	signature: ecdsa/sign key checksum cv-to-sign ctx 'sha256
	ctx/pub-key: ecdh/public key ;= (ecdsa/sign generates new key pair)
	ctx/pub-exp: 'secp256r1
	tls-config [verify: error]
	valid: try [decode-certificate-verify ctx cv-msg 0#0403 signature]
	append last ctx/context-messages #{00}
	invalid: try [decode-certificate-verify ctx cv-msg 0#0403 signature]
	tls-config [verify: log]
	is? reduce [error? valid  did all [error? invalid find form invalid "Decrypt error"]] [#(false) #(true)]
]

--test-- "CertificateVerify with unsupported signature scheme is refused with `verify: error`" [
	ctx: cv-ctx
	tls-config [verify: error]
	e: try [decode-certificate-verify ctx cv-msg 0#0807 #{0102030405}] ;= ed25519
	tls-config [verify: log]
	did all [error? e  find form e "Decrypt error"]
]

summary

Rebol [
	title: "Rebol TLS Server test script"
]

system/options/quiet: false
system/schemes/tls: none
do %build/prot-tls.reb
system/schemes/tls/config [
	verbosity: 5
	groups: [curve25519]
]

;; In case that script is run multiple times from console,
;; close the previous instance.
try [close server]

server: open [
	scheme: 'tls
	port:   8435
	config: [
		;; TLS server requires valid certificate with a public key
		;; and its private key!
		;; These 2 are generated using OpenSSL command:
		;- openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out MyCertificate.crt -keyout MyKey.key
		;; For public use you may need authorized certificate (https://letsencrypt.org/)
		certificates: %certs/MyCertificate.crt
		private-key:  %certs/MyKey.key
	]
]

;; The TLS server port is used like a TCP server port:
;; it receives `accept` events and `first server` returns the new client connection.
server/awake: func [event [event!] /local client][
	if event/type = 'accept [
		client: first event/port
		sys/log/info 'REBOL ["New client:" client/spec/ref]
		client/awake: :client-awake
		read client
	]
	false
]
;; Client connections receive `read`, `wrote` and `close` events with decrypted data.
client-awake: func [event [event!] /local port][
	port: event/port
	switch event/type [
		read [
			print to string! port/data
			either find port/data #{0D0A0D0A} [
				write port "HTTP/1.1 200 OK^M^/Content-type: text/plain^M^/Connection: close^M^/^M^/Hello from Rebol using TLS v1.3"
			][	read port ] ;; request not complete yet
		]
		wrote [close port]
		close [close port]
	]
	false
]

sys/log/info 'REBOL ["Waiting for connections..." server/spec/ref]

wait [server]

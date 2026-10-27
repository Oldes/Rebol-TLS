Rebol [
	title: "Rebol/TLS CI test"
]

print ["Running test on Rebol build:" mold to-block system/build]
system/options/quiet: false
system/options/log/rebol:   4
system/options/log/http:    0
system/options/log/cookies: 0

;; Ensure that a fresh extension is loaded:
try [system/modules/tls: none]
try [system/schemes/tls: none]

unless value? 'print-hline [print-hline: :print-horizontal-line]

;; Load local developmnent TLS scheme:
do %build/prot-tls.reb

system/schemes/tls/set-verbose 2

fails: []

foreach url [
	https://example.com
	https://seznam.cz
	https://github.com
	https://google.com
	https://rosettacode.org/wiki/Rosetta_Code ;= supports only TLS1.3 - blocked from CI!
	https://www.rebol.com
	https://codeberg.org ;= sends NEW_SESSION_TICKET in the same fragment like FINISHED
	https://www.tribunalecatania.it ;= has invalid extension; supports only TLS1.2
	https://statsapi.mlb.com/api/v1/gameTypes ;= use TLS1.2 with rss_pss signature algorithm
	https://facebook.com ;= handshake fragment is received in multiple chunks
][
	print-hline
	print [as-yellow "Trying to read:" as-green url]
	print-hline
	try/with [
		;; read/all does not throw on HTTP errors: [status headers body]
		;; so any error here is a TLS (or connection) failure
		res: read/all url
		print-hline
		print ["HTTP status:" res/1 "server:" res/2/Server]
		either res/1 < 400 [
			? res
		][
			;; TLS works, but the server refused the request
			;; (e.g. Cloudflare's bot protection on GitHub runners)
			print as-purple ajoin ["TLS OK, HTTP " res/1 " not tested"]
		]
		print-hline
		print "^/^/"
	][
		sys/log/error 'TEST err: copy system/state/last-error
		repend fails [url err]
	]
]

unless empty? fails [
	print as-red "TEST FAILED!"
	foreach [url err] fails [
		sys/log/error 'TEST ["Read url:" as-yellow url]
		sys/log/error 'TEST err: system/state/last-error
	]
	quit/return 1
]
print 'DONE
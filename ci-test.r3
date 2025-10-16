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

;; Load local developmnent TLS scheme:
do %build/prot-tls.reb

system/schemes/tls/set-verbose 2

fails: []

foreach url [
	https://example.com
	https://seznam.cz
	https://github.com
	https://google.com
	https://rosettacode.org/wiki/Rosetta_Code ;= supports only TLS1.3
	https://www.rebol.com
	https://codeberg.org ;= sends NEW_SESSION_TICKET in the same fragment like FINISHED
	https://www.tribunalecatania.it ;= has invalid extension; supports only TLS1.2
][
	print-horizontal-line
	print [as-yellow "Trying to read:" as-green url]
	print-horizontal-line
	try/with [
		data: read url
		print-horizontal-line
		? data
		print-horizontal-line
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
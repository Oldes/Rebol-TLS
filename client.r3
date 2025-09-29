Rebol [
	title: "Rebol TLS Client test script"
]
system/options/quiet: false
system/schemes/tls: none
do %build/prot-tls.reb
system/schemes/tls/config [
	verbosity: 5
	groups: [curve25519 secp256r1]
]

url: as url! any [select system/options/args "-url" _ https://localhost:8435]

result:
read url
;print read https://127.0.0.1:4433 ;8435
;read https://localhost:4433
;read https://www.google.com
;read https://rosettacode.org/wiki/Rosetta_Code
;read https://github.com
;read https://www.seznam.cz
;read https://seznam.cz
;read https://localhost:11111 ;4433
? result
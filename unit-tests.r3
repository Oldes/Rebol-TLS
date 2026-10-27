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
	ctx: make TLS-context [
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

summary

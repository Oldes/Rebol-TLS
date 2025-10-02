Rebol [
    Title:  "TLS Protocol"
    File:   %tls.reb
    Name:    'tls
    Yype:    'module
    Author: "Oldes"
    License: MIT ;= SPDX-License-Identifier
    Home:    https://github.com/Oldes/Rebol-TLS
    Version: 0.10.1
    Date:    02-Oct-2025
]
try [do "_: #(none)"] ;; backward compatibility
#include %tls-context.reb
#include %tls-constants.reb
#include %tls-utils.reb
#include %tls-crypto.reb
#include %tls-certificate.reb
#include %tls-protocol.reb
#include %tls-client.reb
#include %tls12-client.reb
#include %tls-server.reb
#include %tls-scheme.reb
#include %tls-cipher-suites.reb
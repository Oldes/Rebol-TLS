Rebol [
    title: "TLS Protocol"
    SPDX-License-Identifier: Apache-2
    name:  tls
    type:  module
    author: "Oldes"
    file: %tls-prot.reb
    home: https://github.com/Oldes/Rebol-TLS
    Version: 0.10.0
    Date: 30-Sep-2025
]

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
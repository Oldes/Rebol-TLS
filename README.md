![rebol-tls](https://github.com/user-attachments/assets/2356d7f2-8880-440f-8240-7306cdf34453)

[![Rebol-TLS CI](https://github.com/Oldes/Rebol-TLS/actions/workflows/main.yml/badge.svg)](https://github.com/Oldes/Rebol-TLS/actions/workflows/main.yml)
[![Gitter](https://badges.gitter.im/rebol3/community.svg)](https://app.gitter.im/#/room/#Rebol3:gitter.im)
[![Zulip](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://rebol.zulipchat.com/#narrow/stream/371632-Rebol.2FHTTPd)

# Rebol/TLS: Transport Layer Security for [Rebol3][1]

Rebol/TLS is a pure Rebol3 implementation of the Transport Layer Security (TLS) protocol, version 1.3. It provides a `tls://` scheme that enables Rebol applications to establish secure, encrypted communication channels over TCP. This implementation offers both client-side and server-side TLS functionalities, allowing developers to build secure clients and servers entirely within the Rebol environment.

This repository contains the source code split into multiple parts for better maintenance and development (see [Module Structure](#module-structure)).

The legacy TLS implementation [`prot-tls12.reb`][4] (originally written by Cyphre) was present in Rebol prior to version `3.20.0`.  
It is included only for a historical purposes.

## NOTE!

**The current state has not been fully tested and may not be stable.**

## Features

- **TLS 1.3 Implementation**: A comprehensive implementation of the TLS 1.3 protocol, as specified in [RFC 8446][5], written entirely in Rebol3.
- **TLS 1.2 Client Support**: Client implementation for TLS 1.2 to ensure compatibility with systems that have not yet upgraded to TLS 1.3.
- **Rebol Scheme**: Integrates seamlessly into Rebol's port and scheme system, providing a familiar `tls://` URL scheme for secure networking.
- **Client and Server Support**: Contains example scripts and core logic for both TLS clients and TLS servers. The server side supports only TLS 1.3.
- **Pure Rebol Code**: The protocol logic is implemented in Rebol, making it easily inspectable, modifiable, and extensible by Rebol developers. It relies on underlying cryptographic primitives, which are typically provided by the Rebol interpreter or extensions.
- **Modular Design**: The codebase is organized into modules for different aspects of TLS, such as cipher suites, certificate handling, cryptographic operations, protocol state machines, and context management.

## Installation

Rebol/TLS is designed to work with a Rebol3 interpreter that supports user-defined schemes and provides the necessary cryptographic primitives, including SHA-256, HMAC, AEAD ciphers like AES-GCM, and key exchange functions such as ECDHE. The build result of this repository, [`prot-tls.reb`][3] (the _preprocessed_ `tls.reb` file), is included in the Rebol3 interpreter since version `3.20.0` (older versions include the legacy implementation).

For development purposes, to replace the official Rebol TLS implementation, use the following commands:
```rebol
do %build/prot-tls.reb   ;; Installs the new implementation
```
It is also useful to enable traces for debugging:
```rebol
system/schemes/tls/set-verbose 4 ;; Maximum verbosity
```

## Usage

This TLS scheme is usually transparent to the user and is used internally by higher-level schemes like HTTPS, e.g.:
```rebol
read https://github.com
```
For testing purposes, basic client and server examples are provided (`client.r3` and `server.r3`).  

### Server

A TLS server port is used the same way as a TCP server port. Its `awake` receives an `accept` event when a client finished the TLS handshake and `first server` returns the new connection. The connection's `awake` receives `read`, `wrote` and `close` events with decrypted data in `port/data`:
```rebol
server: open [
    scheme: 'tls
    port:   8435
    config: [
        certificates: %certs/MyCertificate.crt ;; or a block of files (certificate chain)
        private-key:  %certs/MyKey.key
    ]
]
server/awake: func [event /local client][
    if event/type = 'accept [
        client: first event/port
        client/awake: func [event /local port][
            port: event/port
            switch event/type [
                read  [write port "HTTP/1.1 200 OK^M^/Content-Length: 5^M^/^M^/Hello"]
                wrote [close port]
                close [close port]
            ]
            false
        ]
        read client
    ]
    false
]
wait [server]
```

## Tests

Offline unit tests (including a TLS client/server handshake on `localhost`) are run using:
```
rebol3 -s unit-tests.r3
```
They use the build result, so `build/prot-tls.reb` must be rebuilt (using [Siskin][7] and `Rebol-TLS.nest`) after changing the sources. `ci-test.r3` tests reading from real HTTPS servers.

## API Overview

The primary API is through Rebol's standard port functions (`open`, `read`, `write`, `close`, `copy`, `query`, `update`, `awake`) using the `tls://` scheme.

-   **`open tls://host:port`**: Initiates a TLS client connection to `host` on `port`. The TLS handshake is performed as part of the opening process.
-   **`read port`**: Reads data from the established TLS connection.
-   **`write port data`**: Writes `data` to the established TLS connection.
-   **`close port`**: Closes the TLS connection and the underlying TCP socket.

For server-side operations, the API involves creating a TCP listening port and then applying the TLS server logic to accepted connections. This typically means using lower-level port actors or helper functions provided by the TLS modules to manage the handshake and data encryption/decryption.

## Module Structure

The project is organized into several Rebol script files, each handling a specific part of the TLS implementation:

-   `Rebol-TLS.nest`: A project build definition file.
-   `tls.reb`: Main entry point, used to include all other files (`#include` directives are resolved by the build).
-   `tls-scheme.reb`: Defines the TLS scheme actor and port specification.
-   `tls-protocol.reb`: Implements the core TLS 1.3 handshake protocol logic.
-   `tls-client.reb`: Client-side specific handshake logic and state management for TLS 1.3.
-   `tls-server.reb`: Server-side specific handshake logic and state management for TLS 1.3.
-   `tls-crypto.reb`: Wrappers or interfaces to cryptographic primitives (hashing, HMAC, AEAD encryption, key exchange).
-   `tls-cipher-suites.reb`: Definitions and handling of supported TLS cipher suites.
-   `tls-certificate.reb`: Functions for parsing and handling X.509 certificates.
-   `tls-context.reb`: Manages the context or state of a TLS connection (keys, sequence numbers, etc.).
-   `tls-utils.reb`: Utility functions used across the TLS implementation.
-   `tls-constants.reb`: Constants used in the TLS protocol (message types, handshake types, etc.).
-   `tls12-client.reb`: Client-side specific handshake logic for TLS 1.2.
-   `certs/`: Self-signed test certificate and private key (`MyCertificate.crt`, `MyKey.key`) used by the server example and tests.
-   `legacy/`: The legacy TLS 1.2 implementation (`prot-tls12.reb`).
-   `build/`: The build result (`prot-tls.reb`).
-   `client.r3`: Example script demonstrating TLS client usage.
-   `server.r3`: Example script demonstrating TLS server usage.
-   `unit-tests.r3`: Offline unit tests.
-   `ci-test.r3`: Test reading from real HTTPS servers (used in CI).
  
## Contributing

Contributions to improve Rebol/TLS are welcome.

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/Oldes/Rebol-TLS/blob/main/LICENSE) file for details.

## See also
* Rebol3 (active fork & releases): install and runtime binaries. ([GitHub][1])
* Rebol HTTP Server ([GitHub][6])

---

[1]: https://github.com/Oldes/Rebol3 "Oldes/Rebol3: Source code for the Rebol [R3] interpreter"
[2]: https://github.com/Oldes/Rebol-TLS "GitHub - Oldes/Rebol-TLS: Rebol Transport Layer Security (TLS) Protocol and Scheme"
[3]: https://github.com/Oldes/Rebol-TLS/blob/main/build/prot-tls.reb "Preprocessed build result"
[4]: https://github.com/Oldes/Rebol-TLS/blob/main/legacy/prot-tls12.reb "TLS Protocol used in version prior Rebol 3.20.0"
[5]: https://datatracker.ietf.org/doc/html/rfc8446 "RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3"
[6]: https://github.com/Oldes/Rebol-HTTPd "Rebol HTTP server"
[7]: https://github.com/Siskin-framework/Builder "Siskin Builder"


<img width="2878" height="1704" alt="tls" src="https://github.com/user-attachments/assets/b0f2c9d9-1d45-4cd9-932b-69c750bc174d" />


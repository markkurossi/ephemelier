# The Ephemelier Operating System

The Ephemelier operating system is an MPC virtual machine and
execution environment. It executes programs in the "MPC space"
i.e. the Ephemelier nodes can't access the memory or the computation
of the programs.

## Example

The following commands are run in the `cmd/ephemelier` directory.

First, start the evaluator node:

``` shell
$ ./ephemelier -e -ktrace
Ephemelier Evaluator Node
Listening for MPC connections at :9000
```

Next, start the garbler node:

``` shell
./ephemelier -ktrace -console
Ephemelier Garbler Node
Console running at :2323
```

Finally, connect to the console port via telnet:

``` shell
$ telnet localhost 2323
Trying ::1...
Connected to localhost.
Escape character is '^]'.
Ephemelier v0.0 - Copyright (c) 2025 Markku Rossi
esh $ Ephemelier
Hello, Ephemelier!
esh $ exit
Connection closed by foreign host.
```

# HTTPS Server

## TLS cipher suites

The cipher suite is hardcoded to TLS_CHACHA20_POLY1305_SHA256. To
change it to TLS_AES_128_GCM_SHA256, edit:

 - `mpc/pkg/crypto/tls/cipher.mpcl` to use `gcm.{Seal,Open}AES128`
   instead of `chacha20poly1305.{Seal,Open}`
 - configure cipher suite in `crypto/tls/tls.go`
 - configure cipher key size in `pkg/ephemelier/tlsmem/tlsmem.mpcl`

## TODO

 - [ ] FROST [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.txt)
 - [ ] Circuit stats in streaming mode (INFO)
 - [ ] Optimize input setting (direct vs. via strings)
 - [ ] Review `mpc/otext`
 - [ ] Review `mpc/vole`
 - [ ] Review [SPDZ Implementation](crypto/spdz/)
 - [ ] Implement [Ephemelier State Machine Compiler](cmd/esmc/)
 - [ ] MPC compiler: -timestamp-dynamic option for the -circ mode to
       create timestamp file only if main's arguments have unspecified
       types
 - [ ] WASM as an intermediate language?

# Benchmarks

| HTTPD                 | Time    | Relative |
| :------------         | ------: | -------: |
| 1st roundtrip         | 14.203s | 1.000    |
| Optimized main        | 12.514s | 0.881    |
| Semihonest mem        | 7.183s  | 0.506    |
| ChaCha20Poly1305      | 6.393s  | 0.450    |
| ChaCha20 native block | 5.152s  | 0.363    |

| Fibo           | Time    | Relative |
| :------------  | ------: | -------: |
| Baseline       | 2.736s  | 1.000    |
| Semihonest mem | 0.814s  | 0.298    |

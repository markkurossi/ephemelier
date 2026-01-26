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

## Creating HTTPS private key and certificate

``` shell
$ cd cmd/apps/ephemelier
$ ../tss/tss keygen
...
E: compressed: 0461108f1e6572a06f75bae4b4b603759e0f31d0cf48fa7fe4583765a185a569bc96209ab639b21dbc6f731e115626e907ae3e6556acb46b486de5c55173d7b862
 ../../../nap/cmd/unspammer/unspammer -ca ../../../nap/cmd/unspammer/nap -create-ee localhost -pubkey 0461108f1e6572a06f75bae4b4b603759e0f31d0cf48fa7fe4583765a185a569bc96209ab639b21dbc6f731e115626e907ae3e6556acb46b486de5c55173d7b862
$ ../vault/vault -o data/vault0/httpd -t P-256 import peer-G.share ee-cert.pem
$ ../vault/vault -o data/vault1/httpd -t P-256 import peer-E.share
```


# TODO

 - [x] [Multi-Party Threshold Signature Scheme](https://github.com/bnb-chain/tss-lib)
 - [x] Circuit stats in streaming mode (INFO)
 - [x] Optimize input setting (direct vs. via strings)
 - [x] Review `mpc/ot`
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
| Optimized input       | 4.956s  | 0.349    |
| New HTTPD             | 5.785s  | 0.407    |
| IKNP OT               | 4.918s  | 0.346    |
| Threshold signatures  | 5.296s  | 0.373    |
| HTTPD memory          | 5.693s  | 0.401    |

| Fibo            | Time    | Relative |
| :------------   | ------: | -------: |
| Baseline        | 2.736s  | 1.000    |
| Semihonest mem  | 0.814s  | 0.298    |
| Optimized input | 0.796s  | 0.291    |
| IKNP OT         | 0.352s  | 0.129    |

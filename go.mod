module github.com/markkurossi/ephemelier

go 1.25.0

require (
	github.com/bytemare/dkg v0.0.0-20241007182121-23ea4d549880
	github.com/bytemare/frost v0.0.0-20241019112700-8c6db5b04145
	github.com/markkurossi/mpc v0.0.0-20251016101200-468005fe4cce
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	filippo.io/nistec v0.0.4 // indirect
	github.com/bytemare/ecc v0.8.2 // indirect
	github.com/bytemare/hash v0.3.0 // indirect
	github.com/bytemare/hash2curve v0.3.0 // indirect
	github.com/bytemare/secp256k1 v0.1.6 // indirect
	github.com/bytemare/secret-sharing v0.7.0 // indirect
	github.com/gtank/ristretto255 v0.2.0 // indirect
	github.com/markkurossi/crypto v0.0.0-20240520115340-daed3f9a1082 // indirect
	github.com/markkurossi/tabulate v0.0.0-20251126123558-a08056f6160f // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
)

replace github.com/markkurossi/mpc => ../mpc

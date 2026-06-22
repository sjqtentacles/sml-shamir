# sml-shamir

[![CI](https://github.com/sjqtentacles/sml-shamir/actions/workflows/ci.yml/badge.svg)](https://github.com/sjqtentacles/sml-shamir/actions/workflows/ci.yml)

Shamir's Secret Sharing over **GF(256)** in pure Standard ML.

Split a secret (any byte string) into `n` shares such that **any `k`** of them
reconstruct it exactly, while **any `k-1`** reveal nothing. Each byte of the
secret becomes the constant term of an independent random polynomial of degree
`k-1` over the AES/Rijndael field GF(256); the shares are that polynomial
evaluated at distinct nonzero abscissae, and reconstruction is Lagrange
interpolation at 0.

This is a single, self-contained `Shamir` structure over the Basis library,
with **no dependencies, no FFI, no threads, and no clock**. Randomness is
*injected* — you supply `randomBytes : int -> string` — so the library carries
no PRNG, stays dependency-free, and is fully deterministic for testing by
feeding it fixed bytes.

Verified on **MLton** and **Poly/ML**; the suite (FIPS-197 GF(256) vectors plus
round-trip, threshold, and independence properties) produces byte-for-byte
identical output across both compilers.

## API

```sml
structure Shamir : sig
  exception Shamir of string

  structure Gf : sig                 (* GF(256), AES polynomial 0x11B *)
    val add : int * int -> int       (* = XOR *)
    val mul : int * int -> int
    val inv : int -> int             (* raises Shamir on 0 *)
  end

  val split   : {secret:string, n:int, k:int, randomBytes:int->string}
                -> (int * string) list
  val combine : (int * string) list -> string
end
```

`split` calls `randomBytes` once with the number of bytes it needs
(`|secret| * (k-1)`) and returns `n` pairs `(index, share)` with indices
`1..n`; each share is the same length as the secret. `combine` takes any
`k` (or more) of those pairs and rebuilds the secret. Indices must be distinct
and nonzero. Invalid parameters raise `Shamir`.

> **Security note.** The confidentiality of the scheme rests entirely on the
> quality of `randomBytes`. In production pass a cryptographically secure RNG;
> the fixed/deterministic generators used in the tests and demo are for
> reproducibility only.

### Example

```sml
(* `myRandom` should be a CSPRNG returning that many bytes. *)
val shares = Shamir.split
  {secret = "correct horse battery staple", n = 5, k = 3, randomBytes = myRandom}

(* any 3 of the 5 shares reconstruct the secret *)
val secret = Shamir.combine [List.nth (shares, 1),
                             List.nth (shares, 3),
                             List.nth (shares, 4)]
(* secret = "correct horse battery staple" *)
```

See [`examples/demo.sml`](examples/demo.sml); run it with `make example`. Its
output is captured in [`examples/demo.out`](examples/demo.out):

```
secret  : "correct horse battery staple"
split into 5 shares (threshold k = 3):
  share 1: 158E2EC743462E982FC7FFAB1409AF4E355B908525483FEA323BEA58
  share 2: DD793BA2D4B2C2DBE5E2940C8BF55E1A96C3CBB4919184CACC1D9956
  share 3: AB986717F2979863A24A19D4FADC9335D7EC3E43CDF9C8549F561F6B
  share 4: 5752097BC5800BBB655B14F092BBD80330884529E9C621410C6B383C
  share 5: 21B355CEE3A5510322F39928E392152C71A7B0DEB5AE6DDF5F20BE01

recombining shares 2, 4, 5:
recovered: "correct horse battery staple"
match    : true
```

## Build & test

Requires [MLton](http://mlton.org/) and/or [Poly/ML](https://polyml.org/).

```sh
make test        # build + run the suite under MLton
make test-poly   # run the suite under Poly/ML
make all-tests   # both
make example     # build + run the demo
make clean
```

## Installing with smlpkg

```sh
smlpkg add github.com/sjqtentacles/sml-shamir
smlpkg sync
```

Reference `lib/github.com/sjqtentacles/sml-shamir/shamir.mlb` from your own
`.mlb` (MLton / MLKit), or feed `sources.mlb` to `tools/polybuild` (Poly/ML).

## Layout

```
sml.pkg                                        smlpkg manifest
Makefile                                       MLton + Poly/ML targets
.github/workflows/ci.yml                       CI: MLton + Poly/ML
lib/github.com/sjqtentacles/sml-shamir/
  shamir.sig     SHAMIR signature
  shamir.sml     GF(256) + split/combine implementation
  sources.mlb    ordered source list
  shamir.mlb     public basis
examples/
  demo.sml       split a key 3-of-5, recover from 3
  demo.out       captured demo output
test/
  harness.sml    shared assertion harness
  test.sml       GF(256) vectors + Shamir property suite (41 checks)
  entry.sml / main.sml
tools/polybuild  Poly/ML build wrapper
```

## Tests

41 deterministic checks:

- **GF(256) arithmetic** — addition (XOR), the canonical FIPS-197
  multiplication examples (`{57}·{83}={C1}`, `{57}·{13}={FE}`, the `xtime`
  chain, `{53}·{CA}={01}`), and multiplicative inverse (`a · a⁻¹ = 1` for all
  255 nonzero elements; `inv 0` raises).
- **Deterministic split** — a hand-computed `2-of-2` vector with fixed bytes,
  and the same fixed bytes reproducing identical shares.
- **Threshold round-trip** — every one of the C(5,3)=10 three-share subsets
  reconstructs the secret; likewise all C(7,4) four-of-seven subsets.
- **Independence** — no `k-1` subset reconstructs the secret.
- **Multi-byte secrets** — empty, a full 256-byte block, a 32-byte key, and the
  edge thresholds `k=1` and `k=n`.
- **Error handling** — `k>n`, `k<1`, `n>255`, empty `combine`, and a short
  `randomBytes` callback all raise.

Run `make all-tests` to verify identical output under both compilers.

## License

MIT. See [LICENSE](LICENSE).

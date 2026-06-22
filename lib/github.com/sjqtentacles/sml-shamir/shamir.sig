(* shamir.sig

   Shamir's Secret Sharing over GF(256).

   A secret (an arbitrary byte string) is split into `n` shares such that any
   `k` of them reconstruct the secret exactly, while any `k-1` reveal nothing
   about it.  Each byte of the secret is the constant term of an independent
   random polynomial of degree `k-1` over GF(256); shares are the polynomial
   evaluated at distinct nonzero abscissae `1..n`.  Reconstruction is Lagrange
   interpolation at 0.

   GF(256) uses the AES / Rijndael reducing polynomial
       x^8 + x^4 + x^3 + x + 1   (0x11B).

   Randomness is *injected*: the caller supplies `randomBytes : int -> string`,
   a function returning that many bytes.  The library itself has no source of
   randomness (no FFI, no clock, no PRNG), which keeps it dependency-free and
   makes splitting deterministic for testing by supplying fixed bytes. *)

signature SHAMIR =
sig
  (* Raised on invalid parameters (e.g. k < 1, k > n, n out of 1..255), on a
     `randomBytes` callback that returns too few bytes, or on malformed input
     to `combine` (no shares, duplicate/zero indices, mismatched lengths). *)
  exception Shamir of string

  (* GF(256) arithmetic, exposed for testing and reuse. *)
  structure Gf :
  sig
    val add : int * int -> int   (* field addition (= XOR), 0..255 *)
    val mul : int * int -> int   (* field multiplication, 0..255 *)
    val inv : int -> int         (* multiplicative inverse; raises Shamir on 0 *)
  end

  (* split {secret, n, k, randomBytes}

       secret      the bytes to protect (any length, including "")
       n           number of shares to produce (1..255)
       k           threshold: any k shares reconstruct the secret (1..n)
       randomBytes called once with the number of random bytes required
                   (= |secret| * (k-1)); must return at least that many

     Returns `n` pairs `(i, share)` with distinct indices `i` in `1..n`.  Each
     `share` has the same length as `secret`. *)
  val split : {secret:string, n:int, k:int, randomBytes:int->string}
              -> (int * string) list

  (* combine shares

     Reconstructs the secret from a list of `(index, share)` pairs.  At least
     `k` correct shares are required; supplying exactly the original `k`
     reproduces the secret.  Indices must be distinct and nonzero and all
     shares equal in length. *)
  val combine : (int * string) list -> string
end

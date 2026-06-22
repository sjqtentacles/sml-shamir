structure Tests =
struct

  (* ---- helpers ---- *)

  (* All size-k subsets of a list, preserving order. *)
  fun subsets 0 _ = [[]]
    | subsets _ [] = []
    | subsets k (x :: xs) =
        List.map (fn s => x :: s) (subsets (k - 1) xs) @ subsets k xs

  (* A deterministic byte stream standing in for a CSPRNG, so split/combine
     tests are reproducible.  Returns exactly `n` bytes. *)
  fun fixedRandom n =
    String.implode (List.tabulate (n, fn i => Char.chr ((i * 31 + 7) mod 256)))

  (* Single fixed byte 0x05, for the hand-computed deterministic vector. *)
  fun constRandom n = String.implode (List.tabulate (n, fn _ => Char.chr 0x05))

  fun shareToString (i, s) =
    "(" ^ Int.toString i ^ ",\"" ^ String.toString s ^ "\")"
  fun sharesToString xs = "[" ^ String.concatWith "," (List.map shareToString xs) ^ "]"

  fun runAll () =
    let
      (* ---------- GF(256) arithmetic (AES polynomial 0x11B) ---------- *)
      val () = Harness.section "GF(256) addition (XOR)"
      val () = Harness.checkInt "0x57 + 0x83 = 0xD4" (0xD4, Shamir.Gf.add (0x57, 0x83))
      val () = Harness.checkInt "0x53 + 0xCA = 0x99" (0x99, Shamir.Gf.add (0x53, 0xCA))
      val () = Harness.checkInt "a + 0 = a"          (0x57, Shamir.Gf.add (0x57, 0x00))
      val () = Harness.checkInt "a + a = 0"          (0x00, Shamir.Gf.add (0x57, 0x57))

      val () = Harness.section "GF(256) multiplication (FIPS-197 vectors)"
      val () = Harness.checkInt "0x57 * 0x01 = 0x57" (0x57, Shamir.Gf.mul (0x57, 0x01))
      val () = Harness.checkInt "0x57 * 0x02 = 0xAE" (0xAE, Shamir.Gf.mul (0x57, 0x02))
      val () = Harness.checkInt "0x57 * 0x04 = 0x47" (0x47, Shamir.Gf.mul (0x57, 0x04))
      val () = Harness.checkInt "0x57 * 0x08 = 0x8E" (0x8E, Shamir.Gf.mul (0x57, 0x08))
      val () = Harness.checkInt "0x57 * 0x10 = 0x07" (0x07, Shamir.Gf.mul (0x57, 0x10))
      val () = Harness.checkInt "0x57 * 0x13 = 0xFE" (0xFE, Shamir.Gf.mul (0x57, 0x13))
      val () = Harness.checkInt "0x57 * 0x83 = 0xC1" (0xC1, Shamir.Gf.mul (0x57, 0x83))
      val () = Harness.checkInt "0x53 * 0xCA = 0x01" (0x01, Shamir.Gf.mul (0x53, 0xCA))
      val () = Harness.checkInt "a * 0 = 0"          (0x00, Shamir.Gf.mul (0x57, 0x00))
      val () = Harness.checkInt "0 * a = 0"          (0x00, Shamir.Gf.mul (0x00, 0x57))
      val () = Harness.checkInt "a * 1 = a"          (0xCA, Shamir.Gf.mul (0xCA, 0x01))
      val () = Harness.checkBool "mul commutes"
                 (true, Shamir.Gf.mul (0x57, 0x83) = Shamir.Gf.mul (0x83, 0x57))

      val () = Harness.section "GF(256) inverse"
      val () = Harness.checkInt "inv 0x01 = 0x01" (0x01, Shamir.Gf.inv 0x01)
      val () = Harness.checkInt "inv 0x53 = 0xCA" (0xCA, Shamir.Gf.inv 0x53)
      val () = Harness.checkInt "inv 0xCA = 0x53" (0x53, Shamir.Gf.inv 0xCA)
      val () = Harness.checkBool "a * inv a = 1 (all nonzero)"
                 (true, List.all (fn a => Shamir.Gf.mul (a, Shamir.Gf.inv a) = 1)
                           (List.tabulate (255, fn i => i + 1)))
      val () = Harness.checkRaises "inv 0 raises" (fn () => Shamir.Gf.inv 0)

      (* ---------- Deterministic split (hand-computed vector) ----------
         secret = "S" (0x53), k = 2, n = 2, single random coeff c1 = 0x05.
         p(x) = 0x53 + 0x05*x  over GF(256)
           p(1) = 0x53 + 0x05      = 0x56 = 'V'
           p(2) = 0x53 + (0x05*2)  = 0x53 + 0x0A = 0x59 = 'Y'             *)
      val () = Harness.section "Deterministic split (fixed randomBytes)"
      val det = Shamir.split {secret = "S", n = 2, k = 2, randomBytes = constRandom}
      val () = Harness.checkString "shares match hand-computed vector"
                 (sharesToString [(1, "V"), (2, "Y")], sharesToString det)
      val () = Harness.checkString "round-trip of the vector"
                 ("S", Shamir.combine det)
      (* Same fixed randomness must reproduce the same shares. *)
      val det2 = Shamir.split {secret = "S", n = 2, k = 2, randomBytes = constRandom}
      val () = Harness.checkString "split is deterministic for fixed bytes"
                 (sharesToString det, sharesToString det2)

      (* ---------- split shape ---------- *)
      val () = Harness.section "split shape"
      val secret = "correct horse battery staple"
      val shares5 = Shamir.split {secret = secret, n = 5, k = 3, randomBytes = fixedRandom}
      val () = Harness.checkInt "produces n shares" (5, List.length shares5)
      val () = Harness.checkIntList "indices are 1..n"
                 ([1, 2, 3, 4, 5], List.map #1 shares5)
      val () = Harness.checkBool "every share has secret length"
                 (true, List.all (fn (_, s) => String.size s = String.size secret) shares5)

      (* ---------- round-trip: any k-of-n subset recovers ---------- *)
      val () = Harness.section "any k-of-n subset recovers the secret"
      val combos = subsets 3 shares5  (* all C(5,3) = 10 subsets *)
      val () = Harness.checkInt "there are C(5,3)=10 subsets" (10, List.length combos)
      val () = Harness.checkBool "all 3-of-5 subsets reconstruct"
                 (true, List.all (fn sub => Shamir.combine sub = secret) combos)

      (* ---------- k-1 shares reveal nothing reconstructable ---------- *)
      val () = Harness.section "k-1 shares cannot reconstruct"
      val pairs = subsets 2 shares5  (* all 2-share subsets, below threshold *)
      val () = Harness.checkBool "no 2-of-5 subset yields the secret"
                 (true, List.all (fn sub => Shamir.combine sub <> secret) pairs)

      (* ---------- multi-byte secrets of various sizes ---------- *)
      val () = Harness.section "multi-byte secrets"
      fun roundTrips (secret, n, k) =
        let
          val sh = Shamir.split {secret = secret, n = n, k = k, randomBytes = fixedRandom}
          val pick = List.take (sh, k)
        in Shamir.combine pick = secret end
      val () = Harness.checkBool "empty secret round-trips"
                 (true, roundTrips ("", 5, 3))
      val () = Harness.checkBool "binary secret (all 256 byte values)"
                 (true, roundTrips (String.implode (List.tabulate (256, Char.chr)), 6, 4))
      val () = Harness.checkBool "32-byte key, 2-of-3"
                 (true, roundTrips (String.implode (List.tabulate (32, fn i => Char.chr (i * 7 mod 256))), 3, 2))
      val () = Harness.checkBool "k = 1 (every share is the secret)"
                 (true, roundTrips ("trivial", 4, 1))
      val () = Harness.checkBool "k = n (all shares required)"
                 (true, roundTrips ("threshold equals count", 5, 5))

      (* shares are interchangeable regardless of which k we pick *)
      val km = Shamir.split {secret = "interchangeable", n = 7, k = 4, randomBytes = fixedRandom}
      val () = Harness.checkBool "any 4 of 7 reconstruct"
                 (true, List.all (fn sub => Shamir.combine sub = "interchangeable")
                           (subsets 4 km))

      (* ---------- error handling ---------- *)
      val () = Harness.section "error handling"
      val () = Harness.checkRaises "k > n raises"
                 (fn () => Shamir.split {secret = "x", n = 2, k = 3, randomBytes = fixedRandom})
      val () = Harness.checkRaises "k < 1 raises"
                 (fn () => Shamir.split {secret = "x", n = 2, k = 0, randomBytes = fixedRandom})
      val () = Harness.checkRaises "n > 255 raises"
                 (fn () => Shamir.split {secret = "x", n = 256, k = 2, randomBytes = fixedRandom})
      val () = Harness.checkRaises "combine [] raises"
                 (fn () => Shamir.combine [])
      val () = Harness.checkRaises "randomBytes too short raises"
                 (fn () => Shamir.split {secret = "abc", n = 3, k = 2, randomBytes = fn _ => ""})
    in
      Harness.run ()
    end

  val run = runAll
end

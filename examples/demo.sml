(* demo.sml - split a secret key into 5 shares, then recover it from 3.

   The library takes randomness as an injected `randomBytes : int -> string`.
   A real deployment passes a CSPRNG here; for a reproducible demo we use a
   small deterministic linear congruential generator so the output is the same
   on every run and under both compilers. *)

fun lcgBytes seed n =
  let
    (* Full-period 16-bit LCG (a=25173, c=13849, m=2^16); small enough to stay
       within a fixed-width `int` on every compiler.  We take the high byte,
       which has the better-distributed bits. *)
    fun step s = (25173 * s + 13849) mod 65536
    fun loop (i, s, acc) =
      if i >= n then String.implode (List.rev acc)
      else
        let val s' = step s
        in loop (i + 1, s', Char.chr ((s' div 256) mod 256) :: acc)
        end
  in
    loop (0, seed, [])
  end

fun toHex s =
  String.concat
    (List.map
      (fn c => StringCvt.padLeft #"0" 2 (Int.fmt StringCvt.HEX (Char.ord c)))
      (String.explode s))

val secret = "correct horse battery staple"

val shares = Shamir.split
  {secret = secret, n = 5, k = 3, randomBytes = lcgBytes 1}

fun showShare (i, s) =
  print ("  share " ^ Int.toString i ^ ": " ^ toHex s ^ "\n")

(* Recover using shares 2, 4 and 5 - any 3 of the 5 work. *)
val chosen = [List.nth (shares, 1), List.nth (shares, 3), List.nth (shares, 4)]
val recovered = Shamir.combine chosen

val () =
  ( print ("secret  : \"" ^ secret ^ "\"\n")
  ; print ("split into 5 shares (threshold k = 3):\n")
  ; List.app showShare shares
  ; print ("\nrecombining shares "
           ^ String.concatWith ", " (List.map (Int.toString o #1) chosen)
           ^ ":\n")
  ; print ("recovered: \"" ^ recovered ^ "\"\n")
  ; print ("match    : " ^ Bool.toString (recovered = secret) ^ "\n")
  )

(* shamir.sml

   Shamir's Secret Sharing over GF(256) with the AES reducing polynomial
   x^8 + x^4 + x^3 + x + 1 (0x11B).  See shamir.sig for the contract. *)

structure Shamir :> SHAMIR =
struct
  exception Shamir of string

  (* ---- byte-wise bit operations on plain ints (Basis has none) ---- *)
  fun ixor (a, b) = Word.toInt (Word.xorb (Word.fromInt a, Word.fromInt b))
  fun iand (a, b) = Word.toInt (Word.andb (Word.fromInt a, Word.fromInt b))

  (* Schoolbook GF(256) multiply (Russian-peasant with reduction by 0x11B),
     used once to build the log/antilog tables. *)
  fun mulSlow (a, b) =
    let
      fun loop (a, b, p) =
        if b = 0 then p
        else
          let
            val p  = if iand (b, 1) = 1 then ixor (p, a) else p
            val hi = iand (a, 0x80)
            val a' = iand (a * 2, 0xFF)
            val a' = if hi <> 0 then ixor (a', 0x1B) else a'
          in
            loop (a', b div 2, p)
          end
    in
      loop (a, b, 0)
    end

  (* Exp/log tables base the generator g = 3 (a primitive element of the
     field).  expT.(i) = g^i for i in 0..254 (period 255); logT.(g^i) = i. *)
  val expT = Array.array (255, 0)
  val logT = Array.array (256, 0)
  val () =
    let
      fun build (i, x) =
        if i = 255 then ()
        else ( Array.update (expT, i, x)
             ; Array.update (logT, x, i)
             ; build (i + 1, mulSlow (x, 3)) )
    in
      build (0, 1)
    end

  structure Gf =
  struct
    fun add (a, b) = ixor (a, b)

    fun mul (a, b) =
      if a = 0 orelse b = 0 then 0
      else Array.sub (expT, (Array.sub (logT, a) + Array.sub (logT, b)) mod 255)

    fun inv a =
      if a = 0 then raise Shamir "GF(256) inverse of zero"
      else Array.sub (expT, (255 - Array.sub (logT, a)) mod 255)
  end

  (* ---- splitting ---- *)

  fun split {secret, n, k, randomBytes} =
    let
      val () = if k < 1 then raise Shamir "k must be >= 1" else ()
      val () = if n < 1 orelse n > 255
               then raise Shamir "n must be in 1..255" else ()
      val () = if k > n then raise Shamir "k must be <= n" else ()

      val len    = String.size secret
      val degree = k - 1
      val needed = len * degree
      val rnd    = randomBytes needed
      val () = if String.size rnd < needed
               then raise Shamir "randomBytes returned too few bytes" else ()

      (* coefficient of x^p (p in 1..degree) for byte position j *)
      fun coeff (j, p) = Char.ord (String.sub (rnd, j * degree + (p - 1)))
      fun secretByte j = Char.ord (String.sub (secret, j))

      (* Horner-free evaluation: secret + c1*x + c2*x^2 + ... at abscissa x. *)
      fun evalAt (j, x) =
        let
          fun loop (p, xp, acc) =          (* xp = x^p *)
            if p > degree then acc
            else
              let
                val acc' = Gf.add (acc, Gf.mul (coeff (j, p), xp))
              in
                loop (p + 1, Gf.mul (xp, x), acc')
              end
        in
          loop (1, x, secretByte j)
        end

      fun shareAt x =
        (x, String.implode (List.tabulate (len, fn j => Char.chr (evalAt (j, x)))))
    in
      List.tabulate (n, fn i => shareAt (i + 1))
    end

  (* ---- reconstruction (Lagrange interpolation at 0) ---- *)

  fun combine shares =
    let
      val () = case shares of [] => raise Shamir "no shares supplied" | _ => ()
      val xs = List.map #1 shares
      val () = if List.exists (fn x => x = 0) xs
               then raise Shamir "share index 0 is invalid" else ()
      val len =
        case shares of
            (_, s) :: rest =>
              ( if List.all (fn (_, t) => String.size t = String.size s) rest
                then String.size s
                else raise Shamir "shares differ in length" )
          | [] => 0

      (* Reconstruct byte position j across all supplied points.
         secret_j = SUM_i  y_ij * PROD_{m<>i} x_m / (x_i + x_m)        *)
      fun interp j =
        let
          fun term ((xi, si), acc) =
            let
              val yi = Char.ord (String.sub (si, j))
              fun prod ([], num, den) = (num, den)
                | prod ((xm, _) :: rest, num, den) =
                    if xm = xi then prod (rest, num, den)
                    else prod (rest, Gf.mul (num, xm),
                                     Gf.mul (den, Gf.add (xi, xm)))
              val (num, den) = prod (shares, 1, 1)
              val li = Gf.mul (num, Gf.inv den)
            in
              Gf.add (acc, Gf.mul (yi, li))
            end
        in
          List.foldl term 0 shares
        end
    in
      String.implode (List.tabulate (len, fn j => Char.chr (interp j)))
    end
end

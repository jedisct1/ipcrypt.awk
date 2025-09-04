#!/usr/bin/awk -f
# Unified ipcrypt AWK implementation supporting variants:
#   deterministic (variant=det)  AES-128 over 16-byte IP block
#   nd            (variant=nd)   KIASU-BC with 8-byte tweak padded to 16
#   ndx           (variant=ndx)  AES-XTS style (two 16-byte keys, 16-byte tweak)
#
# Common params:
#   mode=enc|dec variant=det|nd|ndx
#   key=HEX (32 hex for det/nd, 64 hex for ndx)
#
# Variant specific params:
#   det enc: ip=IP            -> outputs encrypted IP (text form)
#   det dec: ip=ENCRYPTED_IP  -> outputs original IP
#
#   nd  enc: ip=IP [tweak=16HEX] -> outputs 48 hex (8B tweak || 16B ciphertext)
#            (random tweak generated if omitted; NOT cryptographically strong)
#   nd  dec: data=48HEX          -> outputs original IP (key required)
#
#   ndx enc: ip=IP [tweak=32HEX] -> outputs 64 hex (16B tweak || 16B ciphertext)
#       dec: data=64HEX          -> outputs original IP (key required)
#
# Notes:
#   * IPv4 mapped to IPv6 (::ffff:0:0/96) internally.
#   * IPv6 textual output is canonical per RFC 5952:
#       - lowercase hex
#       - longest run of >=2 zero hextets compressed (first if tie)
#       - no compression of a single 0 field
#       - each hextet without leading zeros
#     (IPv4-mapped addresses return dotted-decimal IPv4.)
#   * Pure POSIX-ish AWK (no reliance on non-portable bitwise ops, strtonum, etc.).

##############################################################################
# Entry point
##############################################################################
BEGIN {
  parse_args()
  if (variant == "" || mode == "") {
    fail("need variant=det|nd|ndx and mode=enc|dec")
  }
  init_tables()

  if (variant == "det") {
    if (length(keyhex) != 32) fail("det key must be 32 hex")
    hex_to_bytes(keyhex, KEY, 16)
    expand_key(KEY, RK)   # primary schedule

    if (mode == "enc") {
      if (ip == "") fail("need ip")
      ip_to_bytes(ip, PT)
      aes_encrypt_block(PT, CT, RK)
      print bytes_to_ip(CT)"\n"; exit
    } else if (mode == "dec") {
      if (ip == "") fail("need ip=<encrypted ip>")
      ip_to_bytes(ip, CT)
      aes_decrypt_block(CT, PT, RK)
      print bytes_to_ip(PT)"\n"; exit
    } else fail("bad mode")
  }
  else if (variant == "nd") {
    if (length(keyhex) != 32) fail("nd key must be 32 hex")
    hex_to_bytes(keyhex, KEY, 16)
    expand_key(KEY, RK)

    if (mode == "enc") {
      if (ip == "") fail("need ip")
      if (tweakhex != "") {
        if (length(tweakhex) != 16) fail("tweak 16 hex")
        hex_to_bytes(tweakhex, TWEAK8, 8)
      } else {
        pseudo_random_bytes(TWEAK8, 8)
      }
      pad_tweak(TWEAK8, TWEAK16)
      ip_to_bytes(ip, PT)
      kiasu_encrypt(PT, TWEAK16, CT, RK)
      bytes_to_hex(TWEAK8, 8); bytes_to_hex(CT, 16); print "\n"; exit
    } else if (mode == "dec") {
      if (datahex == "" || length(datahex) != 48) fail("need data=48hex")
      split_block_hex(substr(datahex, 1, 16), TWEAK8, 8)
      split_block_hex(substr(datahex, 17), CT, 16)
      pad_tweak(TWEAK8, TWEAK16)
      kiasu_decrypt(CT, TWEAK16, PT, RK)
      print bytes_to_ip(PT)"\n"; exit
    } else fail("bad mode")
  }
  else if (variant == "ndx") {
    if (length(keyhex) != 64) fail("ndx key must be 64 hex")
    hex_to_bytes(substr(keyhex, 1, 32),  K1, 16)
    hex_to_bytes(substr(keyhex, 33),     K2, 16)
    expand_key(K1, RK)   # primary schedule
    expand_key(K2, RK2)  # secondary schedule

    if (mode == "enc") {
      if (ip == "") fail("need ip")
      if (tweakhex != "") {
        if (length(tweakhex) != 32) fail("tweak 32 hex")
        hex_to_bytes(tweakhex, TWEAK16, 16)
      } else {
        pseudo_random_bytes(TWEAK16, 16)
      }
      ip_to_bytes(ip, PT)
      aes_encrypt_block(TWEAK16, ET, RK2)
      for (i = 0; i < 16; i++) TMP[i] = bxor(PT[i], ET[i])
      aes_encrypt_block(TMP, ENC, RK)
      for (i = 0; i < 16; i++) CT[i] = bxor(ENC[i], ET[i])
      bytes_to_hex(TWEAK16, 16); bytes_to_hex(CT, 16); print "\n"; exit
    } else if (mode == "dec") {
      if (datahex == "" || length(datahex) != 64) fail("need data=64hex")
      split_block_hex(substr(datahex, 1, 32), TWEAK16, 16)
      split_block_hex(substr(datahex, 33), CT, 16)
      aes_encrypt_block(TWEAK16, ET, RK2)
      for (i = 0; i < 16; i++) TMP[i] = bxor(CT[i], ET[i])
      aes_decrypt_block(TMP, DEC, RK)
      for (i = 0; i < 16; i++) PT[i] = bxor(DEC[i], ET[i])
      print bytes_to_ip(PT)"\n"; exit
    } else fail("bad mode")
  }
  else fail("unknown variant")
}

##############################################################################
# Argument parsing / errors
##############################################################################
function parse_args(   i, kv) {
  for (i = 1; i < ARGC; i++) {
    if (ARGV[i] ~ /^[A-Za-z0-9_]+=/) {
      split(ARGV[i], kv, /=/)
      A[kv[1]] = kv[2]
      ARGV[i] = ""
    }
  }
  mode     = A["mode"]
  variant  = A["variant"]
  ip       = A["ip"]
  keyhex   = A["key"]
  tweakhex = A["tweak"]
  datahex  = A["data"]
}

function fail(m) { print "Error: " m > "/dev/stderr"; exit 1 }

##############################################################################
# Tables / Bit helpers
##############################################################################
function init_tables(    i, x) {
  if (INIT_DONE) return
  INIT_DONE = 1

  split("63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0 b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75 09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2 cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08 ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16", SBOXTOK, " ")
  split("52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb 54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e 08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25 72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92 6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84 90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06 d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b 3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73 96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e 47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4 1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f 60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61 17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d", INVTOK, " ")
  split("01 02 04 08 10 20 40 80 1b 36", RCONTOK, " ")

  for (i = 0; i < 256; i++) {
    SBOX[i]     = hexval(SBOXTOK[i + 1])
    INV_SBOX[i] = hexval(INVTOK[i + 1])
  }
  for (i = 0; i < 10; i++) RCON[i] = hexval(RCONTOK[i + 1])

  init_bit_helpers()
  for (x = 0; x < 256; x++) {
    m2       = mul2(x)
    MUL2[x]  = m2
    MUL3[x]  = bxor(m2, x)
  }
}

function init_bit_helpers(    i) {
  pow2[0] = 1
  for (i = 1; i < 8; i++) pow2[i] = pow2[i - 1] * 2
}

function bxor(a, b,    i, res, abit, bbit) {
  res = 0
  for (i = 0; i < 8; i++) {
    abit = int(a / pow2[i]) % 2
    bbit = int(b / pow2[i]) % 2
    if (abit != bbit) res += pow2[i]
  }
  return res
}

function mul2(x,    shifted) {
  shifted = (x * 2) % 256
  if (x >= 128) shifted = bxor(shifted, 27)
  return shifted % 256
}

##############################################################################
# Hex / Random helpers
##############################################################################
function hexval(h,    i, c, d, v) {
  v = 0
  for (i = 1; i <= length(h); i++) {
    c = substr(h, i, 1)
    if (c >= "A" && c <= "F") c = tolower(c)
    if (c ~ /[0-9]/) d = c + 0
    else if (c == "a") d = 10
    else if (c == "b") d = 11
    else if (c == "c") d = 12
    else if (c == "d") d = 13
    else if (c == "e") d = 14
    else if (c == "f") d = 15
    else fail("hex digit" c)
    v = v * 16 + d
  }
  return v
}

function hex_to_bytes(hex, a, expected,    i, b) {
  if (length(hex) % 2 != 0) fail("hex even")
  if (expected != "" && length(hex) != expected * 2) fail("expected " expected " bytes")
  n = length(hex) / 2
  for (i = 0; i < n; i++) {
    b    = substr(hex, 2 * i + 1, 2)
    a[i] = hexval(b)
  }
}

function split_block_hex(seg, a, n,    i) {
  if (length(seg) != n * 2) fail("segment len")
  for (i = 0; i < n; i++) a[i] = hexval(substr(seg, 2 * i + 1, 2))
}

function bytes_to_hex(a, n,    i) {
  for (i = 0; i < n; i++) printf "%02x", a[i] % 256
}

function pseudo_random_bytes(o, n,    i) {
  srand()
  for (i = 0; i < n; i++) o[i] = int(rand() * 256)
}

##############################################################################
# IP conversion
##############################################################################
function ip_to_bytes(ip, out) {
  if (ip ~ /\./) parse_ipv4(ip, out)
  else           parse_ipv6(ip, out)
}

function parse_ipv4(ip, out,    p, c, i, v) {
  c = split(ip, p, /\./)
  if (c != 4) fail("ipv4")
  for (i = 0; i < 10; i++) out[i] = 0
  out[10] = 255; out[11] = 255
  for (i = 0; i < 4; i++) {
    v = p[i + 1] + 0
    if (v < 0 || v > 255) fail("octet")
    out[12 + i] = v
  }
}

function parse_ipv6(ip, out,    i, left, right, pl, pr, l, r, missing, hs, k, val, v) {
  if (ip == "::") {
    for (i = 0; i < 16; i++) out[i] = 0
    return
  }
  if (ip ~ /::/) {
    split(ip, LR, /::/)
    left  = LR[1]
    right = LR[2]
    l = left  != "" ? split(left,  pl, /:/) : 0
    r = right != "" ? split(right, pr, /:/) : 0
    missing = 8 - (l + r)
    if (missing < 1) fail("::")
    k = 0
    for (i = 1; i <= l; i++) hs[++k] = pl[i]
    for (i = 0; i < missing; i++) hs[++k] = "0"
    for (i = 1; i <= r; i++) hs[++k] = pr[i]
  } else {
    k = split(ip, hs, /:/)
    if (k != 8) fail("ipv6 parts")
  }
  if (k != 8) fail("expansion")
  for (i = 0; i < 8; i++) {
    val = hs[i + 1]
    if (val == "") val = "0"
    if (val !~ /^[0-9A-Fa-f]{1,4}$/) fail("hextet")
    v       = hexval(val)
    out[2*i]     = int(v / 256)
    out[2*i + 1] = v % 256
  }
}

function bytes_to_ip(b,    i, v, hs, longestStart, longestLen, curStart, curLen, res, isv4) {
  # IPv4-mapped shortcut
  isv4 = 1
  for (i = 0; i < 10; i++) if (b[i] != 0) { isv4 = 0; break }
  if (isv4 && b[10] == 255 && b[11] == 255) return b[12]"."b[13]"."b[14]"."b[15]

  for (i = 0; i < 8; i++) { v = b[2*i] * 256 + b[2*i + 1]; hs[i] = v }

  longestStart = -1; longestLen = 0; curStart = -1; curLen = 0
  for (i = 0; i < 8; i++) {
    if (hs[i] == 0) {
      if (curStart == -1) { curStart = i; curLen = 1 } else curLen++
    } else {
      if (curLen > longestLen && curLen >= 2) { longestStart = curStart; longestLen = curLen }
      curStart = -1; curLen = 0
    }
  }
  if (curLen > longestLen && curLen >= 2) { longestStart = curStart; longestLen = curLen }

  res = ""
  for (i = 0; i < 8; i++) {
    if (longestLen >= 2 && i == longestStart) {
      if (res == "") res = "::"; else res = res "::"
      i += (longestLen - 1)
      continue
    }
    if (res != "" && substr(res, length(res)) != ":") res = res ":"
    res = res sprintf("%x", hs[i])
  }
  if (res == "") res = "::"
  return res
}

##############################################################################
# AES primitives
##############################################################################
function sub_bytes(s,    i) { for (i = 0; i < 16; i++) s[i] = SBOX[s[i]] }
function inv_sub_bytes(s,    i) { for (i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]] }

function shift_rows(s, t) {
  t[0]=s[0];  t[1]=s[5];  t[2]=s[10]; t[3]=s[15]
  t[4]=s[4];  t[5]=s[9];  t[6]=s[14]; t[7]=s[3]
  t[8]=s[8];  t[9]=s[13]; t[10]=s[2]; t[11]=s[7]
  t[12]=s[12];t[13]=s[1]; t[14]=s[6];  t[15]=s[11]
  copy_block(t, s)
}

function inv_shift_rows(s, t) {
  t[0]=s[0];  t[1]=s[13]; t[2]=s[10]; t[3]=s[7]
  t[4]=s[4];  t[5]=s[1];  t[6]=s[14]; t[7]=s[11]
  t[8]=s[8];  t[9]=s[5];  t[10]=s[2]; t[11]=s[15]
  t[12]=s[12];t[13]=s[9]; t[14]=s[6];  t[15]=s[3]
  copy_block(t, s)
}

function mix_columns(s, out,    i, s0, s1, s2, s3) {
  for (i = 0; i < 4; i++) {
    s0 = s[4*i]; s1 = s[4*i+1]; s2 = s[4*i+2]; s3 = s[4*i+3]
    out[4*i]   = bxor(bxor(MUL2[s0], MUL3[s1]), bxor(s2, s3))
    out[4*i+1] = bxor(bxor(s0, MUL2[s1]), bxor(MUL3[s2], s3))
    out[4*i+2] = bxor(bxor(s0, s1), bxor(MUL2[s2], MUL3[s3]))
    out[4*i+3] = bxor(bxor(MUL3[s0], s1), bxor(s2, MUL2[s3]))
  }
  copy_block(out, s)
}

function mul_09(b) { return bxor(MUL2[MUL2[MUL2[b]]], b) }
function mul_0B(b) { return bxor(bxor(MUL2[MUL2[MUL2[b]]], MUL2[b]), b) }

function mul_0D(b,    x2, x4, x8) { x2 = MUL2[b]; x4 = MUL2[x2]; x8 = MUL2[x4]; return bxor(bxor(x8, x4), b) }
function mul_0E(b,    x2, x4, x8) { x2 = MUL2[b]; x4 = MUL2[x2]; x8 = MUL2[x4]; return bxor(bxor(x8, x4), x2) }

function inv_mix_columns(s, out,    i, c0, c1, c2, c3) {
  for (i = 0; i < 4; i++) {
    c0 = s[4*i]; c1 = s[4*i+1]; c2 = s[4*i+2]; c3 = s[4*i+3]
    out[4*i]   = bxor(bxor(mul_0E(c0), mul_0B(c1)), bxor(mul_0D(c2), mul_09(c3)))
    out[4*i+1] = bxor(bxor(mul_09(c0), mul_0E(c1)), bxor(mul_0B(c2), mul_0D(c3)))
    out[4*i+2] = bxor(bxor(mul_0D(c0), mul_09(c1)), bxor(mul_0E(c2), mul_0B(c3)))
    out[4*i+3] = bxor(bxor(mul_0B(c0), mul_0D(c1)), bxor(mul_09(c2), mul_0E(c3)))
  }
  copy_block(out, s)
}

function copy_block(src, dst,    i) { for (i = 0; i < 16; i++) dst[i] = src[i] }

function expand_key(key, RKARR,    round, temp0, temp1, temp2, temp3, j, t, b, pb) {
  for (j = 0; j < 16; j++) RKARR[0, j] = key[j]
  for (round = 0; round < 10; round++) {
    temp0 = RKARR[round, 12]; temp1 = RKARR[round, 13]; temp2 = RKARR[round, 14]; temp3 = RKARR[round, 15]
    t = temp0; temp0 = temp1; temp1 = temp2; temp2 = temp3; temp3 = t
    temp0 = SBOX[temp0]; temp1 = SBOX[temp1]; temp2 = SBOX[temp2]; temp3 = SBOX[temp3]
    temp0 = bxor(temp0, RCON[round])
    for (j = 0; j < 4; j++) {
      if (j == 0) {
        RKARR[round+1, 0] = bxor(RKARR[round, 0], temp0)
        RKARR[round+1, 1] = bxor(RKARR[round, 1], temp1)
        RKARR[round+1, 2] = bxor(RKARR[round, 2], temp2)
        RKARR[round+1, 3] = bxor(RKARR[round, 3], temp3)
      } else {
        b  = 4 * j; pb = 4 * (j - 1)
        RKARR[round+1, b]     = bxor(RKARR[round, b],     RKARR[round+1, pb])
        RKARR[round+1, b + 1] = bxor(RKARR[round, b + 1], RKARR[round+1, pb + 1])
        RKARR[round+1, b + 2] = bxor(RKARR[round, b + 2], RKARR[round+1, pb + 2])
        RKARR[round+1, b + 3] = bxor(RKARR[round, b + 3], RKARR[round+1, pb + 3])
      }
    }
  }
}

function aes_encrypt_block(pt, ct, RKARR,    s, i, j) {
  for (i = 0; i < 16; i++) s[i] = bxor(pt[i], RKARR[0, i])
  for (i = 1; i <= 9; i++) {
    sub_bytes(s); shift_rows(s); mix_columns(s)
    for (j = 0; j < 16; j++) s[j] = bxor(s[j], RKARR[i, j])
  }
  sub_bytes(s); shift_rows(s)
  for (i = 0; i < 16; i++) ct[i] = bxor(s[i], RKARR[10, i])
}

function aes_decrypt_block(ct, pt, RKARR,    s, i, r, j) {
  for (i = 0; i < 16; i++) s[i] = bxor(ct[i], RKARR[10, i])
  inv_shift_rows(s); inv_sub_bytes(s)
  for (r = 9; r > 0; r--) {
    for (i = 0; i < 16; i++) s[i] = bxor(s[i], RKARR[r, i])
    inv_mix_columns(s); inv_shift_rows(s); inv_sub_bytes(s)
  }
  for (i = 0; i < 16; i++) pt[i] = bxor(s[i], RKARR[0, i])
}

##############################################################################
# KIASU (nd variant)
##############################################################################
function pad_tweak(t8, t16,    i) {
  for (i = 0; i < 4; i++) {
    t16[4*i]   = t8[2*i]
    t16[4*i+1] = t8[2*i+1]
    t16[4*i+2] = 0
    t16[4*i+3] = 0
  }
}

function kiasu_encrypt(pt, tweak16, ct, RKARR,    state, j, i) {
  for (i = 0; i < 16; i++) state[i] = bxor(bxor(pt[i], RKARR[0, i]), tweak16[i])
  for (i = 0; i < 9; i++) {
    sub_bytes(state); shift_rows(state); mix_columns(state)
    for (j = 0; j < 16; j++) state[j] = bxor(bxor(state[j], RKARR[i + 1, j]), tweak16[j])
  }
  sub_bytes(state); shift_rows(state)
  for (i = 0; i < 16; i++) ct[i] = bxor(bxor(state[i], RKARR[10, i]), tweak16[i])
}

function kiasu_decrypt(ct, tweak16, pt, RKARR,    state, i, r) {
  for (i = 0; i < 16; i++) state[i] = bxor(bxor(ct[i], RKARR[10, i]), tweak16[i])
  inv_shift_rows(state); inv_sub_bytes(state)
  for (r = 9; r > 0; r--) {
    for (i = 0; i < 16; i++) state[i] = bxor(bxor(state[i], RKARR[r, i]), tweak16[i])
    inv_mix_columns(state); inv_shift_rows(state); inv_sub_bytes(state)
  }
  for (i = 0; i < 16; i++) pt[i] = bxor(bxor(state[i], RKARR[0, i]), tweak16[i])
}


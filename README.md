# ipcrypt AWK Implementations (det, nd, ndx)

Pure AWK implementations for all three variants of the [IPCrypt](https://ipcrypt-std.github.io/) specification:

* `det`  – Deterministic AES-128 over the 16‑byte IP block
* `nd`   – KIASU-BC (8‑byte tweak padded to 16 bytes internally)
* `ndx`  – XTS-like (two AES-128 keys + 16‑byte tweak)

## Features

* Pure portable AWK (no GNU-specific bitwise ops required)
* IPv4 and IPv6 support (IPv4 mapped to IPv6 internally)
* All official test vectors pass
* Deterministic output when a tweak is provided (nd / ndx); optional pseudo-random tweak generation otherwise

## Unified Script Usage

Deterministic encryption (variant `det`):

```sh
awk -f ipcrypt.awk variant=det mode=enc \
    ip=192.0.2.1 \
    key=2b7e151628aed2a6abf7158809cf4f3c
```

Deterministic decryption:

```sh
awk -f ipcrypt.awk variant=det mode=dec \
    ip=1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777 \
    key=2b7e151628aed2a6abf7158809cf4f3c
```

`nd` encryption (provide 8‑byte tweak = 16 hex for reproducibility):

```sh
awk -f ipcrypt.awk variant=nd mode=enc \
    ip=0.0.0.0 \
    key=0123456789abcdeffedcba9876543210 \
    tweak=08e0c289bff23b7c
```
 
Output (48 hex) = tweak(16) || ciphertext(32).

`nd` decryption:

```sh
awk -f ipcrypt.awk variant=nd mode=dec \
    data=08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16 \
    key=0123456789abcdeffedcba9876543210
```
 

`ndx` encryption (two 16‑byte keys concatenated = 64 hex, 16‑byte tweak = 32 hex):

```sh
awk -f ipcrypt.awk variant=ndx mode=enc \
    ip=0.0.0.0 \
    key=0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301 \
    tweak=21bd1834bc088cd2b4ecbe30b70898d7
```
 
Output (64 hex) = tweak(32) || ciphertext(32).

`ndx` decryption:

```sh
awk -f ipcrypt.awk variant=ndx mode=dec \
    data=21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5 \
    key=0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301
```

If `tweak` is omitted for `nd` it generates 8 random bytes; for `ndx` it generates 16 random bytes (not cryptographically strong—use supplied tweaks when determinism or security matters).

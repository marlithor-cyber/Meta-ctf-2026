# Vegetable

## Summary

This challenge ships an encrypted workstation dataset, a ransomware sample, and a memory dump archive. The clean solve path is:

1. identify how the ransomware stores encrypted files
2. recover the live AES key from memory instead of trying to break RSA
3. decrypt the `.veg` files
4. read the flag from the recovered UAP PDF

Flag:

`MetaCTF{53arch1ng_m3m0ry_f0r_4r3a_51}`

## Files

- `encrypted_files.zip`
- `memdump.zip`
- `encrypted_files/ransom.bin`
- `encrypted_files/ransom_pub.pem`
- `encrypted_files/enc_key.bin`

I also kept the helper scripts used during the solve in this folder:

- `scan_aes_sched.py`
- `solve.py`

## Reversing The Ransomware

Running `strings` on the binary is enough to recover the important behavior:

- files are renamed to `*.veg`
- the malware uses `EVP_aes_256_ofb`
- it writes an RSA-encrypted blob to `enc_key.bin`
- a public key is embedded in the binary

Example strings:

- `EVP_aes_256_ofb`
- `%s.veg`
- `%s/enc_key.bin`
- `*** Your files have been encrypted ***`

That immediately tells us the victim files were encrypted with AES-256-OFB, while the random AES key was wrapped with RSA and written to `enc_key.bin`.

The public key is available, but the private key is not, so directly recovering the AES key from the wrapped blob is not the practical route.

## Recovering The AES Key From Memory

The provided memory dump is the important artifact here. The helper script `scan_aes_sched.py` scans selected RAM regions for 32-byte values that look like the start of an AES-256 key schedule.

The filter uses AES-256 key expansion relations on 32-bit words:

- `w8 = w0 ^ g(w7)`
- `w9 = w1 ^ w8`
- `w10 = w2 ^ w9`
- `w11 = w3 ^ w10`
- `w12 = w4 ^ h(w11)`
- `w13 = w5 ^ w12`
- `w14 = w6 ^ w13`
- `w15 = w7 ^ w14`

The script does not fully evaluate the S-box transforms in RAM. Instead, it uses the XOR relations that still hold across later words and then validates each candidate against known file signatures from several encrypted samples:

- DOCX/XLSX should decrypt to `PK\x03\x04`
- PDF should decrypt to `%PDF`
- PNG should decrypt to `\x89PNG`

That quickly isolates the real key:

```text
35f676c3bb7887449793f0e8afb6c3573b3cda719121e8e8a7feceaae97f4af2
```

## Decrypting The Files

The encrypted file format is simple:

- first 16 bytes: IV
- remaining bytes: AES-256-OFB ciphertext

The included solver walks every `.veg` file recursively, uses the first 16 bytes as the IV, decrypts the rest with the recovered key, and writes the plaintext tree back out.

Example:

```bash
python3 solve.py \
  --encrypted-dir . \
  --output-dir decrypted \
  --skip-unzip
```

Local result:

```text
[+] Decrypted 93 files into .../decrypted
[+] Flag: MetaCTF{53arch1ng_m3m0ry_f0r_4r3a_51}
```

## Flag Location

After decryption, the flag is on page 4 of:

`Projects/UAP/UAP_SAUCER_HARDWARE_SPEC__Sophia_Walker__rev3.pdf`

You can extract it directly with:

```bash
pdftotext -f 4 -l 4 decrypted/Projects/UAP/UAP_SAUCER_HARDWARE_SPEC__Sophia_Walker__rev3.pdf -
```

Relevant line:

`MetaCTF{53arch1ng_m3m0ry_f0r_4r3a_51}`

## Notes

The important observation is that the challenge is not asking you to defeat RSA. The ransomware already used the AES key, so the memory dump is enough to recover it and decrypt everything cleanly.

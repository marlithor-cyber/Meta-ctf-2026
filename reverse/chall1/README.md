# License to Reverse

## Summary

The challenge provides a PIE ELF called `license_to_rev`, a small `embedded.zip`, and an extracted `license.txt`. The program wants a license file, verifies it against an embedded copy, checks the `EXPIRY_DATE`, and if the license is still valid it prints a decrypted message.

The supplied license is already the correct one, but it is expired. The flag can still be recovered statically because the final output is just an XOR between a 35-byte blob in `.rodata` and the first 35 bytes of the valid license.

Flag:

`MetaCTF{y0u_g0t_@_g0ld3n_ey3_4_r3v}`

## Files

- `license_to_rev`
- `embedded.zip`
- `extracted/license.txt`

## Recon

Strings already reveal most of the control flow:

- `That is not the correct license. Invalid license.`
- `This license has expired. Please contact support for a new license.`
- `EXPIRY_DATE=`
- `license.txtPK`
- symbols `EMBEDDED_ZIP` and `ENCRYPTED_MESSAGE`

Running the binary with the provided license:

```bash
./license_to_rev extracted/license.txt
```

returns:

```text
This license has expired. Please contact support for a new license.
```

So the file is accepted structurally, but fails the date check.

## Main Logic

`main` does four important things:

1. read the user-supplied file into memory
2. inflate the embedded ZIP payload and recover an internal `license.txt`
3. compare the supplied file against that embedded license with `memcmp`
4. parse `EXPIRY_DATE=YYYY-MM-DD`, compare it against `localtime(time(NULL))`, and only then decrypt

The useful parts of the disassembly are:

- `0x12dd` to `0x12f8`: compare the input license against the embedded one
- `0x1371` to `0x13cb`: search for `EXPIRY_DATE=` and parse it with `sscanf`
- `0x146f` to `0x14a2`: decrypt and print the final message

The decryption loop is extremely small:

```c
for (i = 0; i < 0x23; i++) {
    putc(ENCRYPTED_MESSAGE[i] ^ license[i], stdout);
}
```

So once we know the correct license bytes, we do not need to patch the binary at all.

## Why The Provided License Is Enough

The embedded ZIP contains a `license.txt`, and it matches the extracted file byte-for-byte:

```bash
unzip -p embedded.zip license.txt
```

The important line is:

```text
EXPIRY_DATE=2026-02-01
```

Because today is after February 1, 2026, the binary stops before printing the decrypted message. But the correct license contents are already available locally, so the XOR can be reproduced offline.

## Recovering The Flag

`ENCRYPTED_MESSAGE` lives in `.rodata` at `0x21e0` and is 35 bytes long (`0x23` bytes total, ending before `EMBEDDED_ZIP` at `0x2220`).

The plaintext is:

```python
plaintext[i] = encrypted_message[i] ^ license_bytes[i]
```

Using the first 35 bytes of `license.txt` gives:

```text
MetaCTF{y0u_g0t_@_g0ld3n_ey3_4_r3v}
```

## Solver

The included solver reads the binary, slices out `ENCRYPTED_MESSAGE`, reads the provided license, XORs the two buffers, and prints the flag:

```bash
python3 solve.py
```

Output:

```text
MetaCTF{y0u_g0t_@_g0ld3n_ey3_4_r3v}
```

## Notes

An alternative solve is to patch or debug the expiry branch and let the program print the message itself. The static XOR route is cleaner because the program already contains both required inputs:

- the encrypted message in `.rodata`
- the exact valid license in the embedded ZIP / extracted file

#!/usr/bin/env python3
from pathlib import Path
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MEM = Path('memdump/memdump.raw')
REGIONS = [
    (5393665672, 5847587464),
    (6562118280, 6802118280),
]

samples = {
    'docx': Path('HR/employee_profile_sophia_walker.docx.veg').read_bytes(),
    'xlsx': Path('Finance/ti_budget_fy2026.xlsx.veg').read_bytes(),
    'pdf': Path('Downloads/uap_requirements.pdf.veg').read_bytes(),
    'png': Path('HR/sophia_walker_profile.png.veg').read_bytes(),
}
magics = {
    'docx': b'PK\x03\x04',
    'xlsx': b'PK\x03\x04',
    'pdf': b'%PDF',
    'png': b'\x89PNG',
}


def dec4(key: bytes, iv: bytes, c4: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.OFB(iv)).decryptor()
    return d.update(c4)


def test_key_fast(key: bytes):
    ct = samples['docx']
    if dec4(key, ct[:16], ct[16:20]) == magics['docx']:
        mode = 'prefix'
    elif dec4(key, ct[-16:], ct[:4]) == magics['docx']:
        mode = 'suffix'
    else:
        return None

    for nm, ct in samples.items():
        if mode == 'prefix':
            if dec4(key, ct[:16], ct[16:20]) != magics[nm]:
                return None
        else:
            if dec4(key, ct[-16:], ct[:4]) != magics[nm]:
                return None
    return mode


def scan_region(mem_f, region_start: int, region_end: int):
    chunk = 64 * 1024 * 1024
    overlap = 512

    seen = set()
    tested = 0
    matches = []

    mem_f.seek(region_start)
    pos = region_start
    prev = b''

    while pos < region_end:
        to_read = min(chunk, region_end - pos)
        data = mem_f.read(to_read)
        if not data:
            break

        buf = prev + data
        base = pos - len(prev)

        # Align to 4-byte word boundary in absolute-address space.
        mis = base % 4
        start = (4 - mis) % 4
        b2 = buf[start:]
        b2 = b2[: (len(b2) // 4) * 4]
        arr = np.frombuffer(b2, dtype='<u4')

        if len(arr) > 20:
            w1 = arr[1:-14]
            w2 = arr[2:-13]
            w3 = arr[3:-12]
            w5 = arr[5:-10]
            w6 = arr[6:-9]
            w7 = arr[7:-8]
            w8 = arr[8:-7]
            w9 = arr[9:-6]
            w10 = arr[10:-5]
            w11 = arr[11:-4]
            w12 = arr[12:-3]
            w13 = arr[13:-2]
            w14 = arr[14:-1]
            w15 = arr[15:]

            mask = (
                ((w9 ^ w1) == w8)
                & ((w10 ^ w2) == w9)
                & ((w11 ^ w3) == w10)
                & ((w13 ^ w5) == w12)
                & ((w14 ^ w6) == w13)
                & ((w15 ^ w7) == w14)
            )

            idx = np.nonzero(mask)[0]
            if idx.size:
                for i in idx.tolist():
                    boff = start + i * 4
                    if boff + 32 > len(buf):
                        continue

                    raw = buf[boff : boff + 32]
                    swap = b''.join(raw[j : j + 4][::-1] for j in range(0, 32, 4))

                    for k in (raw, swap):
                        if k in seen:
                            continue
                        seen.add(k)
                        tested += 1
                        mode = test_key_fast(k)
                        if mode:
                            abs_off = base + boff
                            matches.append((abs_off, mode, k.hex()))
                            print(f"MATCH {abs_off} {mode} {k.hex()}", flush=True)

        pos += len(data)
        prev = buf[-overlap:]

        print(
            f"progress {pos - region_start}/{region_end - region_start} bytes, tested={tested}, matches={len(matches)}",
            flush=True,
        )

    return tested, matches


def main():
    total_tested = 0
    all_matches = []

    with MEM.open('rb') as f:
        for a, b in REGIONS:
            print(f"\n=== scanning region {a}..{b} ({b-a} bytes) ===", flush=True)
            tested, matches = scan_region(f, a, b)
            total_tested += tested
            all_matches.extend(matches)

    print(f"\nDONE tested={total_tested} matches={len(all_matches)}", flush=True)
    for m in all_matches:
        print("MATCH_ROW", m, flush=True)


if __name__ == '__main__':
    main()

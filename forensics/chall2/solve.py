#!/usr/bin/env python3
"""
Vegetable CTF Forensics solver.

Workflow:
1) Optional: unzip memdump.zip with password "infected".
2) Decrypt all *.veg files using AES-256-OFB (first 16 bytes = IV).
3) Extract the real MetaCTF flag from page 4 of the UAP PDF.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import zipfile
from pathlib import Path

from Cryptodome.Cipher import AES

DEFAULT_KEY_HEX = "35f676c3bb7887449793f0e8afb6c3573b3cda719121e8e8a7feceaae97f4af2"
DEFAULT_ZIP_PASSWORD = "infected"
DEFAULT_UAP_REL = Path("Projects/UAP/UAP_SAUCER_HARDWARE_SPEC__Sophia_Walker__rev3.pdf")
FLAG_RE = re.compile(r"MetaCTF\{[^}\r\n]+\}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve Vegetable CTF ransomware forensics challenge.")
    parser.add_argument(
        "--encrypted-dir",
        type=Path,
        default=Path("."),
        help="Directory containing ransomware-encrypted .veg files (default: current directory).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("decrypted"),
        help="Directory to write decrypted files (default: ./decrypted).",
    )
    parser.add_argument(
        "--key-hex",
        default=DEFAULT_KEY_HEX,
        help="Recovered AES-256 key in hex.",
    )
    parser.add_argument(
        "--memdump-zip",
        type=Path,
        default=Path("memdump.zip"),
        help="Optional memdump zip path to extract first (default: ./memdump.zip).",
    )
    parser.add_argument(
        "--memdump-out",
        type=Path,
        default=Path("memdump"),
        help="Extraction directory for memdump zip (default: ./memdump).",
    )
    parser.add_argument(
        "--zip-password",
        default=DEFAULT_ZIP_PASSWORD,
        help='Password for memdump zip (default: "infected").',
    )
    parser.add_argument(
        "--skip-unzip",
        action="store_true",
        help="Skip memdump zip extraction step.",
    )
    return parser.parse_args()


def maybe_extract_zip(zip_path: Path, out_dir: Path, password: str) -> None:
    if not zip_path.exists():
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(path=out_dir, pwd=password.encode("utf-8"))
    print(f"[+] Extracted {zip_path} -> {out_dir}")


def decrypt_veg_file(src: Path, dst: Path, key: bytes) -> None:
    data = src.read_bytes()
    if len(data) < 16:
        raise ValueError(f"Encrypted file too short: {src}")
    iv = data[:16]
    ct = data[16:]
    pt = AES.new(key, AES.MODE_OFB, iv=iv).decrypt(ct)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(pt)


def decrypt_all_veg(encrypted_dir: Path, output_dir: Path, key: bytes) -> int:
    veg_files = sorted(p for p in encrypted_dir.rglob("*.veg") if p.is_file())
    if not veg_files:
        raise FileNotFoundError(f"No .veg files found under: {encrypted_dir}")

    count = 0
    for src in veg_files:
        rel = src.relative_to(encrypted_dir)
        dst = output_dir / rel.with_suffix("")
        decrypt_veg_file(src, dst, key)
        count += 1
    return count


def extract_page4_text(pdf_path: Path) -> str:
    try:
        from pypdf import PdfReader  # type: ignore

        reader = PdfReader(str(pdf_path))
        if len(reader.pages) < 4:
            return ""
        return reader.pages[3].extract_text() or ""
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["pdftotext", "-f", "4", "-l", "4", str(pdf_path), "-"],
            check=True,
            capture_output=True,
            text=True,
        )
        return proc.stdout
    except Exception:
        return ""


def find_flag_from_uap_pdf(output_dir: Path) -> str:
    uap_pdf = output_dir / DEFAULT_UAP_REL
    if not uap_pdf.exists():
        raise FileNotFoundError(f"Missing decrypted UAP PDF: {uap_pdf}")

    text = extract_page4_text(uap_pdf)
    match = FLAG_RE.search(text)
    if match:
        return match.group(0)

    # Fallback in case page extraction fails but plaintext token is embedded in PDF bytes.
    raw = uap_pdf.read_bytes().decode("latin1", errors="ignore")
    match = FLAG_RE.search(raw)
    if match:
        return match.group(0)

    raise RuntimeError("Flag not found in decrypted UAP PDF.")


def main() -> int:
    args = parse_args()

    if not args.skip_unzip:
        maybe_extract_zip(args.memdump_zip, args.memdump_out, args.zip_password)

    try:
        key = bytes.fromhex(args.key_hex)
    except ValueError:
        print("[-] --key-hex is not valid hex.", file=sys.stderr)
        return 2
    if len(key) != 32:
        print("[-] --key-hex must be exactly 32 bytes (64 hex chars).", file=sys.stderr)
        return 2

    encrypted_dir = args.encrypted_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    count = decrypt_all_veg(encrypted_dir, output_dir, key)
    print(f"[+] Decrypted {count} files into {output_dir}")

    flag = find_flag_from_uap_pdf(output_dir)
    print(f"[+] Flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

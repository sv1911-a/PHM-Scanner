"""Native file triage primitives.

These helpers intentionally avoid shelling out to `file`, `strings`, `binwalk`,
or other external executables. They provide deterministic first-pass file
analysis that can be extended over time.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class Signature:
    name: str
    artifact_type: str
    offset: int
    magic: bytes
    mime: str = "application/octet-stream"
    extensions: tuple[str, ...] = ()


SIGNATURES: tuple[Signature, ...] = (
    Signature("PNG image", "image", 0, b"\x89PNG\r\n\x1a\n", "image/png", ("png",)),
    Signature("JPEG image", "image", 0, b"\xff\xd8\xff", "image/jpeg", ("jpg", "jpeg")),
    Signature("GIF image", "image", 0, b"GIF8", "image/gif", ("gif",)),
    Signature("PDF document", "document", 0, b"%PDF-", "application/pdf", ("pdf",)),
    Signature("ZIP archive", "archive", 0, b"PK\x03\x04", "application/zip", ("zip", "jar", "docx", "xlsx", "pptx")),
    Signature("Empty ZIP archive", "archive", 0, b"PK\x05\x06", "application/zip", ("zip",)),
    Signature("Spanned ZIP archive", "archive", 0, b"PK\x07\x08", "application/zip", ("zip",)),
    Signature("Gzip archive", "archive", 0, b"\x1f\x8b\x08", "application/gzip", ("gz",)),
    Signature("Bzip2 archive", "archive", 0, b"BZh", "application/x-bzip2", ("bz2",)),
    Signature("XZ archive", "archive", 0, b"\xfd7zXZ\x00", "application/x-xz", ("xz",)),
    Signature("7-Zip archive", "archive", 0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", ("7z",)),
    Signature("RAR archive v4", "archive", 0, b"Rar!\x1a\x07\x00", "application/vnd.rar", ("rar",)),
    Signature("RAR archive v5", "archive", 0, b"Rar!\x1a\x07\x01\x00", "application/vnd.rar", ("rar",)),
    Signature("ELF binary", "binary", 0, b"\x7fELF", "application/x-elf", ("elf", "so")),
    Signature("DOS/PE executable", "binary", 0, b"MZ", "application/vnd.microsoft.portable-executable", ("exe", "dll", "sys")),
    Signature("Mach-O 32-bit", "binary", 0, b"\xfe\xed\xfa\xce", "application/x-mach-binary", ("macho",)),
    Signature("Mach-O 64-bit", "binary", 0, b"\xfe\xed\xfa\xcf", "application/x-mach-binary", ("macho",)),
    Signature("Mach-O Universal", "binary", 0, b"\xca\xfe\xba\xbe", "application/x-mach-binary", ("macho",)),
    Signature("SQLite database", "document", 0, b"SQLite format 3\x00", "application/vnd.sqlite3", ("sqlite", "db")),
    Signature("Windows Registry hive", "document", 0, b"regf", "application/x-ms-registry", ("dat",)),
)


def analyze_file(path: str | Path, max_strings: int = 200) -> dict[str, Any]:
    file_path = Path(path)
    data = file_path.read_bytes()
    signatures = detect_signatures(data)
    return {
        "path": str(file_path),
        "name": file_path.name,
        "size": len(data),
        "hashes": file_hashes(data),
        "entropy": shannon_entropy(data),
        "signatures": signatures,
        "extension": file_path.suffix.lower().lstrip("."),
        "extension_matches_signature": extension_matches(file_path, signatures),
        "strings": extract_strings(data, max_strings=max_strings),
    }


def detect_signatures(data: bytes) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for signature in SIGNATURES:
        if len(data) >= signature.offset + len(signature.magic) and data[signature.offset : signature.offset + len(signature.magic)] == signature.magic:
            matches.append(
                {
                    "name": signature.name,
                    "artifact_type": signature.artifact_type,
                    "offset": signature.offset,
                    "magic_hex": signature.magic.hex(),
                    "mime": signature.mime,
                    "extensions": list(signature.extensions),
                }
            )
    return matches


def extension_matches(path: Path, signatures: list[dict[str, Any]]) -> bool | None:
    if not signatures:
        return None
    extension = path.suffix.lower().lstrip(".")
    if not extension:
        return None
    return any(extension in signature.get("extensions", []) for signature in signatures)


def file_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - forensic identifier, not security use
        "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324 - forensic identifier, not security use
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1
    entropy = 0.0
    for count in frequencies:
        if count:
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def extract_strings(data: bytes, min_length: int = 4, max_strings: int = 200) -> list[str]:
    strings: list[str] = []
    current: bytearray = bytearray()
    for byte in data:
        if 32 <= byte <= 126 or byte in {9}:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(current.decode("ascii", errors="replace"))
                if len(strings) >= max_strings:
                    return strings
            current = bytearray()
    if len(current) >= min_length and len(strings) < max_strings:
        strings.append(current.decode("ascii", errors="replace"))

    # Minimal UTF-16LE string pass.
    if len(strings) < max_strings:
        current_chars: list[str] = []
        for index in range(0, len(data) - 1, 2):
            code = data[index] | (data[index + 1] << 8)
            if 32 <= code <= 126 or code == 9:
                current_chars.append(chr(code))
            else:
                if len(current_chars) >= min_length:
                    strings.append("".join(current_chars))
                    if len(strings) >= max_strings:
                        break
                current_chars = []
    return strings[:max_strings]

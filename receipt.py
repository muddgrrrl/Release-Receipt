#!/usr/bin/env python3
"""Check a macOS ZIP's SHA-256 and read the architecture of its app executables."""

import argparse
import hashlib
import hmac
import json
import plistlib
import re
import struct
import sys
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from xml.parsers.expat import ExpatError

DIGEST = re.compile(r"[0-9a-fA-F]{64}")
SUM_LINE = re.compile(r"([0-9a-fA-F]{64}) [ *](.+)")
CPU_NAMES = {7: "i386", 12: "arm", 0x01000007: "x86_64", 0x0100000C: "arm64"}
THIN = {
    b"\xfe\xed\xfa\xce": (">", 28),
    b"\xce\xfa\xed\xfe": ("<", 28),
    b"\xfe\xed\xfa\xcf": (">", 32),
    b"\xcf\xfa\xed\xfe": ("<", 32),
}
FAT = {
    b"\xca\xfe\xba\xbe": (">", "IIIII"),
    b"\xbe\xba\xfe\xca": ("<", "IIIII"),
    b"\xca\xfe\xba\xbf": (">", "IIQQII"),
    b"\xbf\xba\xfe\xca": ("<", "IIQQII"),
}


class InspectionError(ValueError):
    """The input could not be inspected safely."""


@dataclass(frozen=True)
class Bundle:
    path: str
    architectures: tuple[str, ...]


def expected_hash(path: Path, archive_name: str) -> str:
    matches = []
    with path.open(encoding="utf-8") as checksums:
        for line in checksums:
            match = SUM_LINE.fullmatch(line.rstrip("\r\n"))
            if match and match[2] in (archive_name, f"./{archive_name}"):
                matches.append(match[1].lower())
    if len(matches) != 1:
        raise InspectionError(f"expected exactly one SHA-256 entry for {archive_name!r}")
    return matches[0]


def architecture_name(cpu: int) -> str:
    return CPU_NAMES.get(cpu, f"cpu-0x{cpu:08x}")


def read_architectures(file, size: int) -> tuple[str, ...]:
    prefix = file.read(8)
    if len(prefix) != 8:
        raise InspectionError("truncated executable header")
    magic = prefix[:4]
    if magic in THIN:
        endian, minimum_header = THIN[magic]
        if size < minimum_header or len(file.read(minimum_header - 8)) != minimum_header - 8:
            raise InspectionError("truncated Mach-O header")
        return (architecture_name(struct.unpack(endian + "I", prefix[4:])[0]),)
    if magic not in FAT:
        raise InspectionError("unsupported executable format")

    endian, entry_format = FAT[magic]
    count = struct.unpack(endian + "I", prefix[4:])[0]
    entry = struct.Struct(endian + entry_format)
    table_length = entry.size * count
    if not 1 <= count <= 64 or 8 + table_length > size:
        raise InspectionError("invalid Mach-O architecture count")
    table = file.read(table_length)
    if len(table) != table_length:
        raise InspectionError("truncated Mach-O architecture table")

    architectures = []
    for cpu, _, offset, length, *_ in entry.iter_unpack(table):
        if offset < 8 + table_length or length < 28 or offset + length > size:
            raise InspectionError("Mach-O slice is outside the executable")
        name = architecture_name(cpu)
        if name not in architectures:
            architectures.append(name)
    return tuple(architectures)


def inspect_bundles(archive) -> list[Bundle]:
    with zipfile.ZipFile(archive) as zip_file:
        members = {}
        for item in zip_file.infolist():
            members.setdefault(item.filename, []).append(item)

        found = []
        for name, candidates in sorted(members.items()):
            path = PurePosixPath(name)
            if len(path.parts) < 3 or path.parts[-2:] != ("Contents", "Info.plist"):
                continue
            if path.is_absolute() or ".." in path.parts or path.parts[0] == "__MACOSX":
                continue
            if not path.parts[-3].endswith(".app"):
                continue
            if len(candidates) != 1:
                raise InspectionError(f"ambiguous Info.plist in {str(path.parent.parent)!r}")

            with zip_file.open(candidates[0]) as plist:
                data = plist.read(65537)
            if len(data) > 65536:
                raise InspectionError("Info.plist exceeds 64 KiB")
            try:
                info = plistlib.loads(data)
            except (plistlib.InvalidFileException, ExpatError, ValueError, TypeError, OverflowError) as error:
                raise InspectionError(f"invalid Info.plist in {str(path.parent.parent)!r}") from error
            executable = info.get("CFBundleExecutable") if isinstance(info, dict) else None
            if not isinstance(executable, str) or not executable or "/" in executable or executable in (".", ".."):
                raise InspectionError("invalid CFBundleExecutable")
            binary = str(path.parent / "MacOS" / executable)
            candidates = members.get(binary, [])
            if len(candidates) != 1:
                raise InspectionError(f"missing or ambiguous executable {binary!r}")
            with zip_file.open(candidates[0]) as executable_file:
                architectures = read_architectures(executable_file, candidates[0].file_size)
            found.append(Bundle(str(path.parent.parent), architectures))
    if not found:
        raise InspectionError("no macOS app bundles were found")
    return found


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    expected = parser.add_mutually_exclusive_group()
    expected.add_argument("--expected", metavar="SHA256", help="expected 64-digit SHA-256")
    expected.add_argument("--checksums", type=Path, help="SHA256SUMS file containing the archive name")
    parser.add_argument("--require-universal", action="store_true", help="require arm64 and x86_64 in each app")
    parser.add_argument("--json", action="store_true", help="print a machine-readable report")
    args = parser.parse_args(argv)
    if args.expected and not DIGEST.fullmatch(args.expected):
        parser.error("--expected must contain 64 hexadecimal digits")

    try:
        trusted = expected_hash(args.checksums, args.archive.name) if args.checksums else args.expected
        with args.archive.open("rb") as archive:
            digest = hashlib.file_digest(archive, "sha256").hexdigest()
            if trusted and not hmac.compare_digest(digest, trusted.lower()):
                print(f"Checksum mismatch for {args.archive.name!r}. Observed {digest}.", file=sys.stderr)
                return 2
            archive.seek(0)
            bundles = inspect_bundles(archive)
        universal = all({"arm64", "x86_64"}.issubset(bundle.architectures) for bundle in bundles)
        if args.json:
            print(json.dumps({
                "archive": args.archive.name, "sha256": digest, "checksum_verified": trusted is not None,
                "universal": universal, "bundles": [asdict(bundle) for bundle in bundles],
            }, indent=2))
        else:
            print(f"SHA-256: {digest} ({'matches' if trusted else 'computed'})")
            for bundle in bundles:
                print(f"{bundle.path!r}: {', '.join(bundle.architectures)}")
        if args.require_universal and not universal:
            print("At least one app lacks arm64 or x86_64.", file=sys.stderr)
            return 3
        return 0
    except (OSError, InspectionError, RuntimeError, NotImplementedError, UnicodeError, zipfile.BadZipFile) as error:
        print(f"Could not inspect archive: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

import lief
import struct
import hashlib
import os
 

def get_file_hashes(path: str) -> dict[str, str]:
  hashes = {
      "md5": hashlib.md5(), 
      "sha1": hashlib.sha1(), 
      "sha256": hashlib.sha256(),
      "sha512": hashlib.sha512(),
        }

  with open(path, "rb") as f:
    while chunk := f.read(65536):  # reading chunks in 64 KB
      for h in hashes.values():
        h.update(chunk)

  return {name: h.hexdigest() for name, h in hashes.items()}


# defining format
def defination_format(path):  
    with open(path, "rb") as f:
        file = f.read(64)

    if file[:4] == b"\x7fELF":
        return "ELF"

    if file[:2] == b"MZ":
        e_lfanew = struct.unpack("<I", file[0x3C:0x40])[0]
        with open(path, "rb") as f:
            f.seek(e_lfanew)
            if f.read(4) == b"PE\x00\x00":
                return "PE"

    return "UNKNOWN"


# defining bitness of system
def detect_bitness(path, fmt):
    with open(path, "rb") as f:
        data = f.read(0x1000)

    if fmt == "ELF":
        return {1: 32, 2: 64}.get(data[4])

    if fmt == "PE":
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        magic = struct.unpack("<H", data[e_lfanew + 24:e_lfanew + 26])[0]
        return {0x10B: 32, 0x20B: 64}.get(magic)

    return None


def load(path):
    if os.path.isdir(path):
        raise IsADirectoryError(f"This is a folder, not a file: {path}")

    fmt = defination_format(path)
    if fmt == "UNKNOWN":
        raise ValueError("Neiter ELF nor PE")

    hashes = get_file_hashes(path)
    bits = detect_bitness(path, fmt)
    binary = lief.parse(path)
    if binary is None:
        raise ValueError("LIEF was unable to disassemble the file")

    return fmt, bits, binary, hashes

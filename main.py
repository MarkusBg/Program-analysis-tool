import sys
from report import build_report, format_text
from loader import load
from analyzer import analyze
from yara_scan import scan

path = sys.argv[1] if len(sys.argv) > 1 else r"C:\путь\к\файлу.exe"
print(format_text(build_report(path)))

fmt, bits, binary, hashes = load(path)

print(f"Format: {fmt}, bitness: {bits}, entry point: {hex(binary.entrypoint)}")


print("\n--- Sections ---")
for s in binary.sections:
    print(f"{s.name:10} size: {s.size:8}  entropy: {s.entropy:.2f}")

print("\n--- findings ---")
findings = analyze(binary, fmt) + scan(path)

if not findings:
    print("Nothing suspucious were found")
else:
    order = {"high": 0, "medium": 1, "low": 2}
    for level, msg in sorted(findings, key=lambda x: order[x[0]]):
        print(f"[{level.upper()}] {msg}")

print("\n--- Hashes ---")
for name, value in hashes.items():
    print(f"{name}: {value}")
import base64

s = "qgqvhlbxgiwtcmbqgizc2mjqge="

print(f"Input: {s}")
print(f"Length: {len(s)}")
print()

# Try Base32 with padding fix
def try_b32(data):
    # Add padding if needed (Base32 needs length divisible by 8)
    padding = (8 - len(data) % 8) % 8
    padded = data.upper() + "=" * padding
    print(f"Trying Base32 with padding: {padded}")
    try:
        decoded = base64.b32decode(padded)
        print(f"  Decoded bytes: {decoded}")
        print(f"  As hex: {decoded.hex()}")
        print(f"  As string: {decoded.decode('utf-8', errors='replace')}")
    except Exception as e:
        print(f"  Error: {e}")

# Try Base64
def try_b64(data):
    # Add padding if needed
    padding = (4 - len(data) % 4) % 4
    padded = data + "=" * padding
    print(f"Trying Base64 with padding: {padded}")
    try:
        decoded = base64.b64decode(padded)
        print(f"  Decoded bytes: {decoded}")
        print(f"  As hex: {decoded.hex()}")
        print(f"  As string: {decoded.decode('utf-8', errors='replace')}")
    except Exception as e:
        print(f"  Error: {e}")

# Try Base32 hex variant (0-9, A-V)
def try_b32hex(data):
    padding = (8 - len(data) % 8) % 8
    padded = data.upper() + "=" * padding
    print(f"Trying Base32Hex: {padded}")
    try:
        decoded = base64.b32hexdecode(padded)
        print(f"  Decoded bytes: {decoded}")
        print(f"  As hex: {decoded.hex()}")
    except Exception as e:
        print(f"  Error: {e}")

# Strip trailing = and try
stripped = s.rstrip("=")
print("--- With original ---")
try_b32(s.rstrip("="))
print()
try_b64(s.rstrip("="))
print()
try_b32hex(s.rstrip("="))

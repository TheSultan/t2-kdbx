import struct

def parse_kdbx4_header(file_path):
    with open(file_path, "rb") as f:
        # Read the file signature
        signature = f.read(8)
        if signature != b"\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5":
            raise ValueError("Invalid KDBX 4.x file signature.")
        
        print(f"File signature: {signature.hex()}")

        # Read the file version
        version = struct.unpack("<I", f.read(4))[0]
        print(f"File version: {version}")

        # Start parsing the header fields
        fields = {}
        while True:
            field_id = f.read(1)  # Field ID byte
            if field_id == b"\x00":  # End of header fields
                break

            field_length = struct.unpack("<H", f.read(2))[0]  # Length of the field (little-endian)
            field_data = f.read(field_length)  # Read the actual field data

            fields[field_id] = field_data

        print("\nHeader fields:")
        for field_id, data in fields.items():
            print(f"  Field ID {field_id.hex()}: {data.hex()}")

        # Extract specific fields
        encryption_iv = fields.get(b"\x07")  # IV
        kdf_parameters = fields.get(b"\x0D")  # KDF parameters (as binary blob)
        master_seed = fields.get(b"\x04")  # Master seed
        transform_seed = fields.get(b"\x0C")  # Transform seed (for KDF)

        if encryption_iv:
            print(f"\nInitialization Vector (IV): {encryption_iv.hex()}")
        else:
            print("\nInitialization Vector not found!")

        if master_seed:
            print(f"Master Seed: {master_seed.hex()}")

        if transform_seed:
            print(f"Transform Seed: {transform_seed.hex()}")

        if kdf_parameters:
            print("\nKDF Parameters (raw):")
            print(kdf_parameters.hex())
        else:
            print("\nKDF Parameters not found!")

    return {
        "iv": encryption_iv,
        "master_seed": master_seed,
        "transform_seed": transform_seed,
        "kdf_parameters": kdf_parameters,
    }


# Run the parser
file_path = "Passwords.kdbx"  # Replace with your KeePassXC database file path
header_data = parse_kdbx4_header(file_path)

# Save or further process the extracted parameters as needed

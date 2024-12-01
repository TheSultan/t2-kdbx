import struct

def parse_kdbx4_header(file_path):
    with open(file_path, "rb") as f:
        # Step 1: Verify file signature
        signature = f.read(8)
        if signature != b"\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5":
            raise ValueError("Invalid KDBX 4.x file signature.")
        
        print(f"File signature: {signature.hex()}")

        # Step 2: Verify file version
        version = struct.unpack("<I", f.read(4))[0]
        print(f"File version: {version}")

        # Step 3: Parse header fields
        fields = {}
        while True:
            field_id = f.read(1)  # Read 1 byte for the field ID
            if not field_id:
                print("Unexpected end of file while reading field ID.")
                break

            if field_id == b"\x00":  # Field ID 0x00 marks the end of header fields
                print("End of header reached.")
                break

            # Read 4 bytes for the field length (little-endian unsigned integer)
            field_length_bytes = f.read(4)
            if len(field_length_bytes) != 4:
                print("Unexpected end of file while reading field length.")
                break

            field_length = struct.unpack("<I", field_length_bytes)[0]  # Decode as little-endian
            field_data = f.read(field_length)  # Read the field data of the specified length
            if len(field_data) != field_length:
                print("Unexpected end of file while reading field data.")
                break

            fields[field_id] = field_data

        # Step 4: Debug output for all fields
        print("\nHeader fields:")
        for field_id, data in fields.items():
            print(f"  Field ID {field_id.hex()}: {data.hex()}")

        # Step 5: Extract specific fields
        encryption_iv = fields.get(b"\x07")  # IV
        kdf_parameters = fields.get(b"\x0D")  # KDF parameters (binary blob)
        master_seed = fields.get(b"\x04")  # Master seed
        transform_seed = fields.get(b"\x0C")  # Transform seed

        # Step 6: Print extracted fields
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


# Usage example
file_path = "your_database.kdbx"  # Replace with the actual path to your KeePass database
header_data = parse_kdbx4_header(file_path)

# Use the extracted fields as needed for further processing

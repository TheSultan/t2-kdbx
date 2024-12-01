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
        master_seed = fields.get(b"\x04")  # Master seed
        kdf_parameters = fields.get(b"\x0B")  # KDF parameters (binary blob)

        # Step 6: Extract salt and iterations from KDF Parameters
        salt = None
        iterations = None

        if kdf_parameters:
            print(f"\nKDF Parameters (raw): {kdf_parameters.hex()}")

            # Extract salt (32 bytes for AES-256 salt)
            salt = kdf_parameters[:32]  # First 32 bytes could be the salt
            print(f"Salt: {salt.hex()}")

            # Extract iterations (4 bytes after the salt)
            remaining_data = kdf_parameters[32:]  # Everything after the salt
            if len(remaining_data) >= 4:
                iterations = struct.unpack("<I", remaining_data[:4])[0]  # 4 bytes for iterations
                print(f"Iterations: {iterations}")
            else:
                print("Iterations field is too short or missing!")

        else:
            print("KDF Parameters not found.")

        # Step 7: Print extracted fields
        if encryption_iv:
            print(f"\nInitialization Vector (IV): {encryption_iv.hex()}")
        else:
            print("\nInitialization Vector not found!")

        if master_seed:
            print(f"Master Seed: {master_seed.hex()}")
        else:
            print("\nMaster Seed not found!")

    return {
        "iv": encryption_iv,
        "master_seed": master_seed,
        "salt": salt,
        "iterations": iterations,
    }


# Usage example
file_path = "your_database.kdbx"  # Replace with the actual path to your KeePass database
header_data = parse_kdbx4_header(file_path)

# Use the extracted fields as needed for further processing

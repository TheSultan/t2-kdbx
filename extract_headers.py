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
            # Assuming salt is the first part of the KDF parameters and iterations are stored next
            # KDF Parameters format assumption: [salt (length N)] + [iterations (4 bytes)]
            
            # Extract the salt (assuming it starts from the beginning of the KDF parameters and is a fixed size)
            salt_length = struct.unpack("<I", kdf_parameters[0:4])[0]  # The first 4 bytes store the salt length
            salt = kdf_parameters[4:4+salt_length]  # Extract salt based on the length
            
            # Extract the number of iterations (after the salt)
            iterations = struct.unpack("<I", kdf_parameters[4+salt_length:8+salt_length])[0]  # 4 bytes for iterations

        # Step 7: Print extracted fields
        if encryption_iv:
            print(f"\nInitialization Vector (IV): {encryption_iv.hex()}")
        else:
            print("\nInitialization Vector not found!")

        if master_seed:
            print(f"Master Seed: {master_seed.hex()}")
        else:
            print("\nMaster Seed not found!")

        if salt:
            print(f"Salt: {salt.hex()}")
        else:
            print("\nSalt not found!")

        if iterations is not None:
            print(f"Iterations: {iterations}")
        else:
            print("\nIterations not found!")

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

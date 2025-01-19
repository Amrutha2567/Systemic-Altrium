import json
import base64

# Conversion functions
def hex_to_ascii(hex_string):
    """Convert hex string to ASCII JSON string."""
    bytes_data = bytes.fromhex(hex_string)
    try:
        ascii_text = bytes_data.decode('utf-8')
    except UnicodeDecodeError:
        ascii_text = bytes_data.decode('latin-1')  # Handle fallback decoding
    return ascii_text

def ascii_to_hex(ascii_text):
    """Convert ASCII JSON string to hex string."""
    bytes_data = ascii_text.encode('utf-8')
    hex_string = bytes_data.hex()
    return hex_string

def hex_to_unknown(hex_string):
    """Convert hex to unknown string (encoding)."""
    unknown = ""
    chunk_size = 32  # As hinted
    for i in range(0, len(hex_string), chunk_size):
        chunk = hex_string[i:i+chunk_size]
        encoded_chunk = base64.urlsafe_b64encode(bytes.fromhex(chunk)).decode('utf-8')
        unknown += encoded_chunk
    return unknown

def unknown_to_hex(unknown_string):
    """Convert unknown string to hex (decoding)."""
    hex_string = ""
    chunk_size = 44  # Length of base64-encoded 32-hex block
    for i in range(0, len(unknown_string), chunk_size):
        chunk = unknown_string[i:i+chunk_size]
        try:
            decoded_chunk = base64.urlsafe_b64decode(chunk).hex()
            hex_string += decoded_chunk
        except (base64.binascii.Error, ValueError) as e:
            print(f"Decoding error: {e}")
    return hex_string

# Load the JSON data from the file
file_path = "data.json"  # Update the path if needed
with open(file_path, "r") as file:
    data = json.load(file)

# Process all datasets
results = {}

for key, dataset in data.items():
    unknown = dataset["unknown"]
    hex_value = dataset["hex"]
    ascii_text = dataset["ascii_text"]

    # Perform conversions
    decoded_ascii = hex_to_ascii(hex_value)
    encoded_hex_from_ascii = ascii_to_hex(json.dumps(ascii_text))
    generated_unknown = hex_to_unknown(hex_value)
    decoded_hex_from_unknown = unknown_to_hex(unknown)

    # Store results for each dataset
    results[key] = {
        "Original Unknown": unknown,
        "Original Hex": hex_value,
        "Decoded ASCII from Hex": decoded_ascii,
        "Reconstructed Hex from ASCII": encoded_hex_from_ascii,
        "Generated Unknown from Hex": generated_unknown,
        "Decoded Hex from Unknown": decoded_hex_from_unknown,
        "Match Hex to ASCII": decoded_ascii == json.dumps(ascii_text),
        "Match Hex to Unknown": unknown == generated_unknown,
        "Match Unknown to Hex": hex_value == decoded_hex_from_unknown,
    }

# Save the results to a file
output_path = "results.json"
with open(output_path, "w") as output_file:
    json.dump(results, output_file, indent=4)

print(f"Processing complete. Results saved to {output_path}.")

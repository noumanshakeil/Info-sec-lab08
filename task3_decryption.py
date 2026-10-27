from task1_keygen import generate_rsa_keys, print_public_key
from task2_encryption import ask_and_encrypt


def rsa_decrypt(cipher_hex, private_key):
    d, n = private_key

    try:
        c = int(cipher_hex, 16)
    except ValueError:
        raise ValueError("Ciphertext is not valid hexadecimal.")

    if c >= n:
        raise ValueError("Ciphertext is not valid for this key.")

    m = pow(c, d, n)

    length = (m.bit_length() + 7) // 8
    data = m.to_bytes(length, "big")
    return data.decode("utf-8")


def main():
    print("=" * 60)
    print("TASK 3: RSA Decryption")
    print("=" * 60)

    print("Generating keys from Task 1, please wait...")
    public_key, private_key = generate_rsa_keys()
    print_public_key(public_key)
    print()

    plaintext, ciphertext_hex = ask_and_encrypt(public_key)
    print("Ciphertext (hexadecimal):")
    print(ciphertext_hex)
    print()

    decrypted = rsa_decrypt(ciphertext_hex, private_key)
    print("Decrypted plaintext:", decrypted)

    if plaintext == decrypted:
        print("Verification: SUCCESS. Original and decrypted messages match.")
    else:
        print("Verification: FAILED. Messages do not match.")


if __name__ == "__main__":
    main()
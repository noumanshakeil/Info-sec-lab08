from task1_keygen import generate_rsa_keys, print_public_key


def rsa_encrypt(message, public_key):
    e, n = public_key

    data = message.encode("utf-8")

    if len(data) == 0:
        raise ValueError("Message is empty. Please type something.")
    if data[0] == 0:
        raise ValueError("Message must not start with a null character.")

    max_bytes = (n.bit_length() - 1) // 8
    if len(data) > max_bytes:
        raise ValueError(
            f"Message is too long. Maximum is {max_bytes} bytes, "
            f"yours is {len(data)} bytes."
        )

    m = int.from_bytes(data, "big")

    c = pow(m, e, n)

    size = (n.bit_length() + 7) // 8
    return c.to_bytes(size, "big").hex()


def ask_and_encrypt(public_key):
    while True:
        plaintext = input("Enter the plaintext message: ")
        try:
            ciphertext_hex = rsa_encrypt(plaintext, public_key)
            return plaintext, ciphertext_hex
        except ValueError as error:
            print("Error:", error)


def main():
    print("=" * 60)
    print("TASK 2: RSA Encryption")
    print("=" * 60)

    print("Generating keys from Task 1, please wait...")
    public_key, _private_key = generate_rsa_keys()
    print_public_key(public_key)
    print()

    plaintext, ciphertext_hex = ask_and_encrypt(public_key)

    print("Ciphertext (hexadecimal):")
    print(ciphertext_hex)


if __name__ == "__main__":
    main()
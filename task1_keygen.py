import secrets
from math import gcd

KEY_SIZE_BITS = 2048
PUBLIC_EXPONENT = 65537

SMALL_PRIMES = [p for p in range(2, 1000)
                if all(p % q != 0 for q in range(2, int(p ** 0.5) + 1))]


def is_probable_prime(n, rounds=40):
    if n < 2:
        return False

    for sp in SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | (1 << (bits - 2))
        candidate |= 1
        if is_probable_prime(candidate):
            return candidate


def generate_rsa_keys(key_size_bits=KEY_SIZE_BITS):
    e = PUBLIC_EXPONENT
    half = key_size_bits // 2

    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue

        phi = (p - 1) * (q - 1)

        if gcd(e, phi) != 1:
            continue

        n = p * q

        d = pow(e, -1, phi)

        if (d * e) % phi != 1 or n.bit_length() != key_size_bits:
            continue

        return (e, n), (d, n)


def print_public_key(public_key):
    e, n = public_key
    print(f"Modulus n length : {n.bit_length()} bits")
    print(f"Public exponent e: {e}")
    print(f"First 32 hex digits of n: {format(n, 'x')[:32]}...")


def keys_work(public_key, private_key):
    e, n = public_key
    d, _ = private_key
    test_number = 123456789
    return pow(pow(test_number, e, n), d, n) == test_number


def main():
    print("=" * 60)
    print("TASK 1: RSA Key Generation")
    print("=" * 60)
    print("Generating keys, please wait...")
    public_key, private_key = generate_rsa_keys()

    print("Keys generated successfully.")
    print_public_key(public_key)

    if keys_work(public_key, private_key):
        print("Key pair check passed.")
    else:
        print("Key pair check failed. Please run the program again.")


if __name__ == "__main__":
    main()
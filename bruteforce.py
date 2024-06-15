import hashlib
import itertools
import time

def is_valid_password(password):
    """
    Simulates password complexity check (replace with your actual validation)
    """
    # This is a simplified example. A real password check would consider length,
    # character types, and other complexity requirements.
    return len(password) >= 8

def brute_force_sha2(hash_value, max_length=10):
    """
    Attempts to brute-force a SHA2 hash with a maximum password length.

    Args:
        hash_value (str): The SHA2 hash to crack.
        max_length (int, optional): The maximum password length to try. Defaults to 10.

    Returns:
        str: The cracked password if found, otherwise None.
    """

    start_time = time.time()

    # Define character set (adjust based on password complexity)
    char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    for length in range(1, max_length + 1):
        for guess in itertools.product(char_set, repeat=length):
            attempt = ''.join(guess)
            sha2_hash = hashlib.sha256(attempt.encode('utf-8')).hexdigest()

            # Print progress or implement rate limiting here (for educational purposes)
            # if time.time() - start_time > 10:  # Example rate limiting (remove in practice)
            #     print(f"Rate limit reached. Consider increasing max_length or using a more efficient approach.")
            #     return None

            if sha2_hash == hash_value:
                # Validate password complexity (replace with your actual validation)
                if is_valid_password(attempt):
                    return attempt

    return None

if __name__ == "__main__":
    # Ethical reminder: Replace with a non-sensitive hash for demonstration
    hash_to_crack = "e3b0c44298fc1c149afbf4c8996fb92427ae31eead9d706a7a8ba3e228580a77a"  # SHA256 of an empty string (for demo)

    # Set a reasonable maximum password length to avoid excessive computation
    max_length_to_try = 5  # Adjust based on expected password complexity

    cracked_password = brute_force_sha2(hash_to_crack, max_length_to_try)

    if cracked_password:
        print("Cracked password:", cracked_password)
    else:
        print("Password not found within the specified length limit.")

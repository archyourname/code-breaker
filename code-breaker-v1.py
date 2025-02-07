import itertools
import string
import base64
import time
import hashlib

def print_ascii_art():
    ascii_art = r"""
                    __       __                        __              
  _____ ____   ____/ /___   / /_   _____ ___   ____ _ / /__ ___   _____
 / ___// __ \ / __  // _ \ / __ \ / ___// _ \ / __ `// //_// _ \ / ___/
/ /__ / /_/ // /_/ //  __// /_/ // /   /  __// /_/ // ,<  /  __// /    
\___/ \____/ \__,_/ \___//_.___//_/    \___/ \__,_//_/|_| \___//_/  
           ======== coded by PontMedusa ======================   
                                                                       
    """
    print(ascii_art)

def sha256_hash(password):
    """Return the SHA-256 hash of the given password."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def brute_force_sha256_cracker(target_hash, character_set):
    """Brute force a password by trying all combinations of characters."""
    attempts = 0
    length = 1  # Start with length 1

    start_time = time.time()

    while True:
        for guess in itertools.product(character_set, repeat=length):
            guess_password = ''.join(guess)
            attempts += 1
            
            if sha256_hash(guess_password) == target_hash:
                end_time = time.time()
                print(f"Password found: {guess_password}")
                print(f"Attempts: {attempts}")
                print(f"Time taken: {end_time - start_time:.2f} seconds")
                return
            
            if attempts % 1000 == 0:
                print(f"Attempts: {attempts}, Current guess: {guess_password}")

        length += 1

def brute_force_base64_cracker(encoded_password, character_set):
    """Brute force a password by trying all combinations of characters."""
    attempts = 0
    length = 1  # Start with length 1

    start_time = time.time()

    while True:
        for guess in itertools.product(character_set, repeat=length):
            guess_password = ''.join(guess)
            attempts += 1
            
            if base64.b64encode(guess_password.encode('ascii')).decode('ascii') == encoded_password:
                end_time = time.time()
                print(f"Password found: {guess_password}")
                print(f"Attempts: {attempts}")
                print(f"Time taken: {end_time - start_time:.2f} seconds")
                return
            
            if attempts % 1000 == 0:
                print(f"Attempts: {attempts}, Current guess: {guess_password}")

        length += 1

def main():
    print_ascii_art()

    while True:
        print("\nMenu:")
        print("1. Crack a SHA-256 hashed password")
        print("2. Crack a Base64 encoded password")
        print("3. Exit")
        
        choice = input("Select an option (1-3): ")

        if choice == '1':
            target_hash = input("Enter the SHA-256 hash to crack: ")
            character_set = string.ascii_lowercase + string.ascii_uppercase + string.digits
            print(f"Starting brute force attack on SHA-256 hash '{target_hash}'...")
            brute_force_sha256_cracker(target_hash, character_set)

        elif choice == '2':
            encoded_password = input("Enter the Base64 encoded password to crack: ")
            character_set = string.ascii_lowercase + string.ascii_uppercase + string.digits
            print(f"Starting brute force attack on Base64 encoded password '{encoded_password}'...")
            brute_force_base64_cracker(encoded_password, character_set)

        elif choice == '3':
            print("Exiting the program.")
            break

        else:
            print("Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
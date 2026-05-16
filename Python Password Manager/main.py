import json
import os
import hashlib
import logging
from cryptography.fernet import Fernet

CONFIG_FILE = "config.json"
VAULT_FILE = "vault.json"
LOG_FILE = "access.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_key():
    return Fernet.generate_key().decode()

def load_json(filename):
    if not os.path.exists(filename):
        return {}
    with open(filename, "r") as file:
        return json.load(file)

def save_json(filename, data):
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

def setup_master_password():
    config = load_json(CONFIG_FILE)

    if "master_hash" not in config:
        print("Create a master password.")
        password = input("Master password: ")

        config["master_hash"] = hash_password(password)
        config["key"] = generate_key()

        save_json(CONFIG_FILE, config)
        save_json(VAULT_FILE, {})

        logging.info("Master password created.")
        print("Setup complete.")

def authenticate():
    config = load_json(CONFIG_FILE)
    attempts = 0

    while attempts < 3:
        password = input("Enter master password: ")

        if hash_password(password) == config.get("master_hash"):
            logging.info("Successful login.")
            print("Login successful.")
            return True
        else:
            attempts += 1
            logging.warning("Failed login attempt.")
            print("Incorrect master password.")

    print("Too many failed attempts. Program locked.")
    logging.warning("Application locked after 3 failed login attempts.")
    return False

def get_cipher():
    config = load_json(CONFIG_FILE)
    return Fernet(config["key"].encode())

def add_credential():
    vault = load_json(VAULT_FILE)
    cipher = get_cipher()

    account = input("Account name: ")
    username = input("Username/email: ")
    password = input("Password: ")

    encrypted_password = cipher.encrypt(password.encode()).decode()

    vault[account] = {
        "username": username,
        "password": encrypted_password
    }

    save_json(VAULT_FILE, vault)
    logging.info(f"Credential added for account: {account}")
    print("Credential saved securely.")

def view_credentials():
    vault = load_json(VAULT_FILE)
    cipher = get_cipher()

    if not vault:
        print("No credentials saved.")
        return

    for account, data in vault.items():
        decrypted_password = cipher.decrypt(data["password"].encode()).decode()

        print("\nAccount:", account)
        print("Username:", data["username"])
        print("Password:", decrypted_password)

    logging.info("Credentials viewed.")

def delete_credential():
    vault = load_json(VAULT_FILE)

    account = input("Enter account name to delete: ")

    if account in vault:
        del vault[account]
        save_json(VAULT_FILE, vault)
        logging.info(f"Credential deleted for account: {account}")
        print("Credential deleted.")
    else:
        print("Account not found.")

def menu():
    while True:
        print("\nPassword Manager")
        print("1. Add credential")
        print("2. View credentials")
        print("3. Delete credential")
        print("4. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            add_credential()
        elif choice == "2":
            view_credentials()
        elif choice == "3":
            delete_credential()
        elif choice == "4":
            logging.info("User exited application.")
            print("Goodbye.")
            break
        else:
            print("Invalid option.")

def main():
    setup_master_password()

    if authenticate():
        menu()

if __name__ == "__main__":
    main()
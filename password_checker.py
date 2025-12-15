"""Module to get user's username and password to be stored as document in mongodb database.
   Before storage in the environment variables, the password must pass a 4 steps validation process
   and encrypted.
"""
import hashlib
import pymongo.collection
import requests
import datetime
from cryptography.fernet import Fernet
import pymongo
import os
import logging
from typing import Tuple, Any, Optional, List
from pybloom_live import BloomFilter
from pathlib import Path
from dotenv import load_dotenv, set_key
from bson import ObjectId

# Define .env path at module level
ENV_PATH = Path(__file__).parent / ".env"

# Load existing .env once
load_dotenv(dotenv_path=ENV_PATH)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class PasswordChecker:
    def __init__(
        self,
        min_length: int = 8,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        require_digit: bool = True,
        require_special: bool = True,
    ):
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special = require_special
        self.local_file = str(Path(__file__).parent / 'compromised_password.txt')
        self.bloom_filter: Optional[BloomFilter] = None
        self._load_bloom_filter()
    
    def _load_bloom_filter(self) -> None:
        """Load Bloom filter once during initialization."""
        try:
            self.bloom_filter = self.load_compromised_passwords_into_bloom(self.local_file)
        except Exception as e:
            logging.warning(f"Could not load Bloom filter: {e}")
            self.bloom_filter = None

    def get_password_duration(self) -> datetime.timedelta:
        """Get password expiry duration in number of days with retry logic."""
        while True:
            try:
                duration_input = input("How many days should the password last? (default: 90): ").strip()                
                if not duration_input:
                    duration = 90
                else:
                    duration = int(duration_input)                
                if duration <= 0:
                    print("Duration must be a positive integer. Try again.")
                    continue                    
                return datetime.timedelta(days=duration)
            except ValueError:
                print("Invalid input. Please enter a positive number.")
    
    def generate_encryption_key(self) -> bytes:
        """Generate or retrieve an encryption Fernet key and save to .env."""
        encryption_key_str = os.getenv("ENCRYPTION_KEY")
        
        if not encryption_key_str:
            encryption_key_bytes = Fernet.generate_key()
            encryption_key_str = encryption_key_bytes.decode()
            set_key(str(ENV_PATH), "ENCRYPTION_KEY", encryption_key_str)
            os.environ["ENCRYPTION_KEY"] = encryption_key_str
            logging.warning("Generated new encryption key and saved to .env")
        else:
            encryption_key_bytes = encryption_key_str.encode()
        
        logging.info("Encryption key loaded.")
        return encryption_key_bytes
    
    def get_user_credentials(self) -> Tuple[str, str]:
        """Get password input from the user."""
        while True:
            try:
                input_str = input("Enter your new username and new password separated by space: ").strip()
                if not input_str:
                    print("Please enter both username and password.")
                    continue
                
                parts = input_str.split(maxsplit=1)
                if len(parts) != 2:
                    print("Please enter both username and password separated by a space.")
                    continue
                
                username, password = parts
                return username.strip(), password.strip()
            except Exception as e:
                logging.error(f"Error getting credentials: {e}")
                continue
    
    def is_valid(self, password: str) -> Tuple[bool, str]:
        """Check if the password meets the requirements."""
        if len(password) < self.min_length:
            return False, f"Password must be at least {self.min_length} characters long."

        if self.require_uppercase and not any(char.isupper() for char in password):
            return False, "Password must contain at least one uppercase letter."

        if self.require_lowercase and not any(char.islower() for char in password):
            return False, "Password must contain at least one lowercase letter."

        if self.require_digit and not any(char.isdigit() for char in password):
            return False, "Password must contain at least one digit."

        if self.require_special and not any(not char.isalnum() for char in password):
            return False, "Password must contain at least one special character."

        return True, "Password is valid and compliant."
    
    def load_compromised_passwords_into_bloom(self, file_path: str, 
                                            capacity: int = 1000000, 
                                            error_rate: float = 0.001) -> Optional[BloomFilter]:
        """Loads compromised passwords from a file into a Bloom filter."""
        try:
            if not os.path.exists(file_path):
                logging.warning(f"Local password file '{file_path}' not found.")
                return None
            
            bloom = BloomFilter(capacity=capacity, error_rate=error_rate)
            count = 0
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pwd = line.strip()
                    if pwd:
                        bloom.add(pwd)
                        count += 1
            
            logging.info(f"Loaded Bloom filter from '{file_path}' with {count} items.")
            return bloom
            
        except Exception as e:
            logging.error(f"Error loading Bloom filter: {e}")
            return None
    
    def is_password_in_local_file(self, password: str, file_path: str) -> bool:
        """Performs a definitive linear search in the local file."""
        try:
            if not os.path.exists(file_path):
                return False
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if password == line.strip():
                        return True
            return False
        except Exception as e:
            logging.error(f"Error reading local file '{file_path}' for verification: {e}")
            return False
    
    def check_password_via_hibp(self, password: str) -> Tuple[bool, str]:
        """Check if a password has been compromised using the HIBP API."""
        try:
            sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix, suffix = sha1_password[:5], sha1_password[5:]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            headers = {'User-Agent': 'Python-Password-Checker'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                raise RuntimeError(f"HIBP API request failed with status {response.status_code}")
            
            for line in response.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return True, f"This password has been found in {count} known data breaches."
            
            return False, "This password was not found in known data breaches (HIBP check)."
            
        except requests.exceptions.Timeout:
            msg = "Password safety check timed out. Cannot verify with online service."
            logging.error(msg)
            return False, msg
        except requests.exceptions.RequestException as e:
            msg = f"Network error during password safety check: {e}"
            logging.error(msg)
            return False, msg
        except Exception as e:
            logging.error(f"Unexpected error during HIBP API check: {e}")
            return False, f"Could not complete the password safety check: {e}"
    
    def is_compromised(self, password: str) -> Tuple[bool, str]:
        """
        Check if a password has been compromised using a two-level strategy.
        """
        # Level 1: Local Bloom Filter Check
        if self.bloom_filter is not None and password in self.bloom_filter:
            # Verify with linear search to avoid false positives
            if self.is_password_in_local_file(password, self.local_file):
                return True, "Password found in the local database of known compromised passwords."
        
        # Level 2: HIBP API Check
        return self.check_password_via_hibp(password)
    
    def archive_old_password(self, username: str, old_password: str, 
                           key: bytes, collection: pymongo.collection.Collection) -> None:
        """
        Archive the old/expired password in the old_passwords list.
        
        Args:
            username: The username whose password is being archived
            old_password: The password that has expired
            key: Encryption key for securing the old password
            collection: MongoDB collection
        """
        try:
            fernet = Fernet(key)
            
            # Encrypt the old password
            encrypted_old_password = fernet.encrypt(old_password.encode("utf-8"))
            
            # Get current timestamp
            archive_time = datetime.datetime.now()
            
            # Create archive document
            archive_doc = {
                "password": encrypted_old_password,
                "archived_at": archive_time,
                "reason": "password_expired"
            }
            
            # Update user document to add to old_passwords array
            result = collection.update_one(
                {"username": username},
                {
                    "$push": {
                        "old_passwords": {
                            "$each": [archive_doc],
                            "$slice": -10  # Keep only last 10 old passwords
                        }
                    }
                }
            )
            
            if result.modified_count > 0:
                logging.info(f"Archived old password for user '{username}' at {archive_time}")
            else:
                logging.warning(f"Could not archive old password for user '{username}'. User may not exist.")
                
        except Exception as e:
            logging.error(f"Error archiving old password for user '{username}': {e}")
            raise
    
    def is_password_expired(self, username: str, collection: pymongo.collection.Collection,
                          key: bytes) -> Tuple[bool, str]:
        """
        Check if password has expired and archive it if expired.
        
        Args:
            username: Username to check
            collection: MongoDB collection
            key: Encryption key for archiving old password
            
        Returns:
            Tuple[bool, str]: (True, message) if expired, (False, message) if not expired
        """
        try:
            user_data = collection.find_one(
                {"username": username}, 
                {"expiration_date": 1, "encrypted_password": 1, "old_passwords": 1}
            )
            
            if not user_data:
                return False, f"No user found with username: {username}."
            
            if "expiration_date" not in user_data:
                return False, "No expiration date found for this user."
            
            expiration_date = user_data["expiration_date"]
            current_time = datetime.datetime.now()
            
            if current_time > expiration_date:
                # Archive the expired password before returning
                try:
                    # Decrypt the current password
                    fernet = Fernet(key)
                    encrypted_password = user_data.get("encrypted_password")
                    if encrypted_password:
                        old_password = fernet.decrypt(encrypted_password).decode("utf-8")
                        self.archive_old_password(username, old_password, key, collection)
                    else:
                        logging.warning(f"No encrypted password found for user '{username}' to archive")
                except Exception as archive_error:
                    logging.error(f"Failed to archive expired password for user '{username}': {archive_error}")
                
                return True, "Password has expired, use another one."
            else:
                return False, f"Password valid until {expiration_date}."
                
        except pymongo.errors.PyMongoError as e:
            logging.error(f"MongoDB error checking expiry for {username}: {e}")
            return False, "Database error checking password expiry."
    
    def is_already_used(self, password: str, key: bytes, 
                       collection: pymongo.collection.Collection) -> Tuple[bool, str]:
        """
        Check if the password has already been used by any user in the system.
        This checks both current passwords and old_passwords history.
        
        Args:
            password: Password to check
            key: Encryption key
            collection: MongoDB collection
            
        Returns:
            Tuple[bool, str]: (True, message) if already used, (False, message) if not used
        """
        try:
            fernet = Fernet(key)
            
            # Retrieve all user records with password history
            users = collection.find(
                {}, 
                {"encrypted_password": 1, "old_passwords.password": 1}
            )
            
            for user in users:
                # Check current password
                try:
                    encrypted_password = user.get("encrypted_password")
                    if encrypted_password:
                        decrypted_password = fernet.decrypt(encrypted_password).decode("utf-8")
                        if decrypted_password == password:
                            return True, "Password is already used as current password."
                except Exception as decryption_error:
                    logging.warning(f"Could not decrypt current password for user {user.get('_id')}: {decryption_error}")
                
                # Check old passwords
                old_passwords = user.get("old_passwords", [])
                for old_pwd_record in old_passwords:
                    try:
                        if "password" in old_pwd_record:
                            decrypted_old_password = fernet.decrypt(old_pwd_record["password"]).decode("utf-8")
                            if decrypted_old_password == password:
                                archived_time = old_pwd_record.get("archived_at", "unknown time")
                                return True, f"Password was previously used (archived at {archived_time})."
                    except Exception as old_pwd_error:
                        logging.warning(f"Could not decrypt old password for user {user.get('_id')}: {old_pwd_error}")
                        continue
            
            return False, "Password has not been used before."
            
        except pymongo.errors.PyMongoError as e:
            logging.error(f"MongoDB error while checking password history: {e}")
            return False, f"Database error occurred while checking password history."
        except Exception as e:
            logging.error(f"Unexpected error while checking password history: {e}")
            return False, f"An unexpected error occurred while checking password history."
    
    def get_password_history(self, username: str, key: bytes,
                           collection: pymongo.collection.Collection) -> List[dict]:
        """
        Get the password history for a user.
        
        Args:
            username: Username to get history for
            key: Encryption key
            collection: MongoDB collection
            
        Returns:
            List[dict]: List of password history entries with decrypted passwords
        """
        try:
            user_data = collection.find_one(
                {"username": username},
                {"old_passwords": 1}
            )
            
            if not user_data or "old_passwords" not in user_data:
                return []
            
            fernet = Fernet(key)
            history = []
            
            for old_pwd in user_data["old_passwords"]:
                try:
                    decrypted_password = fernet.decrypt(old_pwd["password"]).decode("utf-8")
                    history_entry = {
                        "archived_at": old_pwd.get("archived_at"),
                        "reason": old_pwd.get("reason", "unknown"),
                        "password": decrypted_password  # Only include if needed for display
                    }
                    history.append(history_entry)
                except Exception as e:
                    logging.warning(f"Could not decrypt old password from history: {e}")
                    continue
            
            return history
            
        except Exception as e:
            logging.error(f"Error retrieving password history for {username}: {e}")
            return []
    
    def validate_password(self, username: str, password: str, 
                         key: bytes, collection: pymongo.collection.Collection) -> bool:
        """Validate password through all checks."""
        # 1. Basic validation
        valid, message = self.is_valid(password)
        if not valid:
            logging.warning(f"Password validation failed: {message}")
            return False
        
        # 2. Compromised check
        compromised, message = self.is_compromised(password)
        if compromised:
            logging.warning(f"Password compromised: {message}")
            return False
        
        # 3. Already used check (now includes old_passwords)
        used, message = self.is_already_used(password, key, collection)
        if used:
            logging.warning(f"Password already used: {message}")
            return False
        
        # 4. Expiry check ONLY for existing users
        user_exists = collection.find_one({"username": username})
        if user_exists:
            expired, message = self.is_password_expired(username, collection, key)
            if expired:
                logging.warning(f"Password expired: {message}")
                return False
        
        return True
    
    def store_password_in_vault(self, username: str, password: str, 
                              collection: pymongo.collection.Collection, key: bytes) -> None:
        """
        Store the password securely in the vault after validation.
        For existing users, archives the old password before updating.
        """
        try:
            fernet = Fernet(key)
            
            # Encrypt the new password
            encrypted_password = fernet.encrypt(password.encode("utf-8"))
            
            # Get the current date and time
            creation_date = datetime.datetime.now()
            
            # Get the password duration
            password_duration = self.get_password_duration()
            
            # Determine the password expiration date
            expiration_date = creation_date + password_duration
            
            # Check if user exists
            existing_user = collection.find_one({"username": username})
            
            if existing_user:
                # Archive old password before updating
                try:
                    old_encrypted_password = existing_user.get("encrypted_password")
                    if old_encrypted_password:
                        old_password = fernet.decrypt(old_encrypted_password).decode("utf-8")
                        self.archive_old_password(username, old_password, key, collection)
                except Exception as archive_error:
                    logging.warning(f"Could not archive old password for user '{username}': {archive_error}")
                
                # Update existing user
                collection.update_one(
                    {"username": username},
                    {
                        "$set": {
                            "encrypted_password": encrypted_password,
                            "creation_date": creation_date,
                            "expiration_date": expiration_date,
                            "last_updated": creation_date
                        }
                    }
                )
                logging.info(f"Updated password for user '{username}' in the vault.")
            else:
                # Insert new user
                collection.insert_one(
                    {
                        "username": username,
                        "encrypted_password": encrypted_password,
                        "creation_date": creation_date,
                        "expiration_date": expiration_date,
                        "old_passwords": [],  # Initialize empty old_passwords array
                        "last_updated": creation_date
                    }
                )
                logging.info(f"Created new user '{username}' and stored password in the vault.")
                
        except Exception as e:
            logging.error(f"Error storing password: {e}")
            raise
    
    def force_password_change(self, username: str, collection: pymongo.collection.Collection,
                            key: bytes) -> bool:
        """
        Force a password change for a user by marking their password as expired.
        
        Args:
            username: Username to force password change for
            collection: MongoDB collection
            key: Encryption key for archiving
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            user_data = collection.find_one({"username": username})
            
            if not user_data:
                logging.error(f"User '{username}' not found")
                return False
            
            # Set expiration date to past
            past_date = datetime.datetime.now() - datetime.timedelta(days=1)
            
            result = collection.update_one(
                {"username": username},
                {"$set": {"expiration_date": past_date}}
            )
            
            if result.modified_count > 0:
                logging.info(f"Forced password change for user '{username}'")
                
                # Archive the old password
                try:
                    fernet = Fernet(key)
                    encrypted_password = user_data.get("encrypted_password")
                    if encrypted_password:
                        old_password = fernet.decrypt(encrypted_password).decode("utf-8")
                        self.archive_old_password(username, old_password, key, collection)
                except Exception as archive_error:
                    logging.warning(f"Could not archive password during forced change: {archive_error}")
                
                return True
            else:
                logging.warning(f"Could not force password change for user '{username}'")
                return False
                
        except Exception as e:
            logging.error(f"Error forcing password change for user '{username}': {e}")
            return False
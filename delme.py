#!/usr/bin/env python3
"""
RSA-TOTP Hybrid Encryption System with Microsoft Office File Support.
This module provides the core functionality for secure encryption and decryption
of JSON data and Microsoft Office files using RSA encryption combined with TOTP authentication.

Files are saved in the user's home directory under eCrime_Totp folder.
"""

import os
import sys
import json
import argparse
import base64
import datetime
import shutil
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Union

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import pyotp

# Import other modules from our package
from .key_manager import KeyManager
from .audit_logger import AuditLogger
from .qr_generator import TOTPQRGenerator
from .file_converter import MSFileConverter


def get_base_directory() -> Path:
    """
    Get the base directory for all files (~/eCrime_Totp).
    Creates the directory if it doesn't exist.
    
    Returns:
        Path object for the base directory
    """
    home_dir = Path.home()
    base_dir = home_dir / "eCrime_Totp"
    base_dir.mkdir(exist_ok=True, parents=True)
    return base_dir


class RSATOTPCrypto:
    """
    Core encryption/decryption class using RSA with TOTP verification.
    
    Implements a hybrid cryptosystem where:
    1. Data is encrypted with AES (symmetric)
    2. The AES key is encrypted with RSA (asymmetric)
    3. Decryption requires a valid TOTP code
    
    All files are stored in the user's home directory under eCrime_Totp.
    """
    
    def __init__(self, config_dir: str = None):
        """
        Initialize the encryption system.
        
        Args:
            config_dir: Directory containing configuration and keys, relative to base directory
        """
        # Set up base directory in user's home
        self.base_dir = get_base_directory()
        print(f"Using base directory: {self.base_dir}")
        
        # Set up config directory
        if config_dir:
            self.config_dir = self.base_dir / config_dir
        else:
            self.config_dir = self.base_dir / "config"
        self.config_dir.mkdir(exist_ok=True, parents=True)
        
        # Set up other directories
        self.logs_dir = self.base_dir / "logs"
        self.logs_dir.mkdir(exist_ok=True, parents=True)
        
        self.output_dir = self.base_dir / "output"
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        self.temp_dir = self.base_dir / "temp"
        self.temp_dir.mkdir(exist_ok=True, parents=True)
        
        self.qr_dir = self.base_dir / "qr_codes"
        self.qr_dir.mkdir(exist_ok=True, parents=True)
        
        # Initialize key manager
        self.key_manager = KeyManager(self.config_dir)
        
        # Initialize audit logger
        self.audit_logger = AuditLogger(self.logs_dir / "access.log")
        
        # Initialize file converter
        self.file_converter = MSFileConverter()
        
        # TOTP settings
        self.totp_window = 90  # 90-second window for TOTP codes
        self.totp_digits = 8   # 8-digit TOTP codes
    
    def initialize_system(self, issuer: str, user_email: str) -> str:
        """
        Initialize the system with new RSA keys and TOTP setup.
        
        Args:
            issuer: The issuer name for the TOTP
            user_email: The user email for the TOTP
        
        Returns:
            Path to the generated QR code image
        """
        # Generate RSA key pair if not exists
        if not self.key_manager.has_current_keys():
            self.key_manager.generate_keypair()
            
        # Generate TOTP secret and QR code
        totp_secret = pyotp.random_base32()
        
        # Store TOTP secret (in real-world scenario, this would be encrypted)
        totp_config_path = self.config_dir / "totp_secret.json"
        with open(totp_config_path, 'w') as f:
            json.dump({
                "secret": totp_secret,
                "issuer": issuer,
                "user": user_email,
                "digits": self.totp_digits,
                "interval": self.totp_window
            }, f)
        
        # Generate QR code in the QR directory
        qr_generator = TOTPQRGenerator(output_dir=self.qr_dir)
        qr_path = qr_generator.generate_totp_qr(
            totp_secret, 
            issuer, 
            user_email,
            digits=self.totp_digits,
            interval=self.totp_window
        )
        
        self.audit_logger.log_event(
            "SYSTEM_INIT",
            "SUCCESS",
            user_email,
            details=f"System initialized with new keys and TOTP in {self.base_dir}"
        )
        
        return qr_path
    
    def _generate_aes_key(self) -> bytes:
        """Generate a random AES key."""
        return os.urandom(32)  # 256-bit key
    
    def _encrypt_with_aes(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data with AES-256-GCM.
        
        Returns:
            Tuple of (iv, ciphertext)
        """
        iv = os.urandom(12)  # GCM standard nonce length
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return iv, ciphertext + encryptor.tag
    
    def _decrypt_with_aes(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt data with AES-256-GCM."""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        
        # Extract tag from ciphertext (last 16 bytes)
        tag = ciphertext[-16:]
        actual_ciphertext = ciphertext[:-16]
        
        # Create decryptor with tag
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize_with_tag(tag)
        return plaintext
    
    def _encrypt_aes_key_with_rsa(self, aes_key: bytes) -> bytes:
        """Encrypt the AES key using RSA public key."""
        public_key = self.key_manager.load_public_key()
        
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key
    
    def _decrypt_aes_key_with_rsa(self, encrypted_key: bytes, totp_code: str) -> Optional[bytes]:
        """
        Decrypt the AES key using RSA private key.
        
        Args:
            encrypted_key: RSA-encrypted AES key
            totp_code: TOTP code for authentication
            
        Returns:
            Decrypted AES key if TOTP code is valid, None otherwise
        """
        # Verify TOTP code
        if not self._verify_totp(totp_code):
            return None
            
        private_key = self.key_manager.load_private_key()
        
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_key
    
    def _verify_totp(self, totp_code: str) -> bool:
        """Verify the provided TOTP code."""
        totp_config_path = self.config_dir / "totp_secret.json"
        
        if not totp_config_path.exists():
            raise FileNotFoundError("TOTP configuration not found. Please initialize the system first.")
            
        with open(totp_config_path, 'r') as f:
            totp_config = json.load(f)
            
        totp = pyotp.TOTP(
            totp_config["secret"],
            digits=totp_config["digits"],
            interval=totp_config["interval"]
        )
        
        # Verify with a window to account for timing differences
        return totp.verify(totp_code)
    
    def encrypt_json(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt JSON data.
        
        Args:
            json_data: JSON data to encrypt
            
        Returns:
            Dictionary with encrypted data and metadata
        """
        # Convert JSON to bytes
        data_bytes = json.dumps(json_data).encode('utf-8')
        
        # Generate AES key
        aes_key = self._generate_aes_key()
        
        # Encrypt data with AES
        iv, encrypted_data = self._encrypt_with_aes(data_bytes, aes_key)
        
        # Encrypt AES key with RSA
        encrypted_key = self._encrypt_aes_key_with_rsa(aes_key)
        
        # Prepare result
        result = {
            "ciphertext": base64.b64encode(encrypted_data).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
            "metadata": {
                "encryption_time": datetime.datetime.now().isoformat(),
                "key_version": self.key_manager.get_current_key_version(),
                "totp_window": self.totp_window
            }
        }
        
        return result
    
    def decrypt_json(self, encrypted_data: Dict[str, Any], totp_code: str) -> Optional[Dict[str, Any]]:
        """
        Decrypt JSON data using the provided TOTP code.
        
        Args:
            encrypted_data: Dictionary with encrypted data and metadata
            totp_code: TOTP code for authentication
            
        Returns:
            Decrypted JSON data if TOTP code is valid, None otherwise
        """
        # Extract components
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        iv = base64.b64decode(encrypted_data["iv"])
        encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
        
        # Decrypt AES key with RSA (requires valid TOTP)
        aes_key = self._decrypt_aes_key_with_rsa(encrypted_key, totp_code)
        
        if aes_key is None:
            self.audit_logger.log_event(
                "DECRYPT_ATTEMPT",
                "FAILURE",
                "unknown",
                details="Invalid TOTP code provided"
            )
            return None
            
        # Decrypt data with AES
        decrypted_bytes = self._decrypt_with_aes(ciphertext, aes_key, iv)
        
        # Convert bytes back to JSON
        decrypted_json = json.loads(decrypted_bytes.decode('utf-8'))
        
        self.audit_logger.log_event(
            "DECRYPT_SUCCESS",
            "SUCCESS",
            "authenticated_user",  # In a real system, you'd track the actual user
            details=f"Successfully decrypted data with key version {encrypted_data['metadata'].get('key_version', 'unknown')}"
        )
        
        return decrypted_json
    
    def encrypt_file(self, file_path: str, output_path: str = None) -> str:
        """
        Encrypt a file (Microsoft Office or JSON).
        
        Args:
            file_path: Path to the file to encrypt
            output_path: Optional path where to save the encrypted file
            
        Returns:
            Path to the encrypted file
            
        Raises:
            ValueError: If the file format is not supported
        """
        file_path = Path(file_path)
        
        # Check if file format is supported
        if not self.file_converter.is_supported_format(file_path):
            raise ValueError(f"Unsupported file format: {file_path.suffix}")
        
        # Convert file to JSON representation
        json_data, file_type = self.file_converter.convert_to_json(file_path)
        
        # Add file type to metadata for reconstruction
        json_data['metadata']['original_path'] = str(file_path)
        json_data['metadata']['original_filename'] = file_path.name
        
        # Encrypt the JSON data
        encrypted_data = self.encrypt_json(json_data)
        
        # Add file type to metadata for decryption
        encrypted_data['metadata']['file_type'] = file_type
        
        # Determine output path
        if not output_path:
            output_path = self.output_dir / f"{file_path.stem}_encrypted.ecrypt"
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                output_path = output_path / f"{file_path.stem}_encrypted.ecrypt"
        
        # Save encrypted data
        with open(output_path, 'w') as f:
            json.dump(encrypted_data, f, indent=2)
        
        self.audit_logger.log_event(
            "FILE_ENCRYPT",
            "SUCCESS",
            "user",
            details=f"Encrypted {file_type} file: {file_path.name} -> {output_path}"
        )
        
        return str(output_path)
    
    def decrypt_file(self, encrypted_file: str, totp_code: str, output_path: str = None) -> Optional[str]:
        """
        Decrypt a file using the provided TOTP code.
        
        Args:
            encrypted_file: Path to the encrypted file
            totp_code: TOTP code for authentication
            output_path: Optional path to save the decrypted file
            
        Returns:
            Path to the decrypted file if successful, None otherwise
        """
        encrypted_file_path = Path(encrypted_file)
        
        # Load encrypted data
        try:
            with open(encrypted_file_path, 'r') as f:
                encrypted_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            self.audit_logger.log_event(
                "FILE_DECRYPT_ATTEMPT",
                "FAILURE",
                "unknown",
                details=f"Failed to load encrypted file: {str(e)}"
            )
            raise ValueError(f"Error loading encrypted file: {str(e)}")
        
        # Decrypt the JSON data
        decrypted_json = self.decrypt_json(encrypted_data, totp_code)
        
        if decrypted_json is None:
            return None
        
        # Handle simple JSON files directly
        file_type = encrypted_data.get('metadata', {}).get('file_type', 'json')
        
        # Determine output path
        if not output_path:
            original_filename = decrypted_json.get('metadata', {}).get('original_filename')
            if original_filename:
                output_path = self.output_dir / f"decrypted_{original_filename}"
            else:
                output_path = self.output_dir / f"{encrypted_file_path.stem}_decrypted"
                # Add appropriate extension based on file type
                if file_type == 'word':
                    output_path = output_path.with_suffix('.docx')
                elif file_type == 'excel':
                    output_path = output_path.with_suffix('.xlsx')
                elif file_type == 'powerpoint':
                    output_path = output_path.with_suffix('.pptx')
                else:
                    output_path = output_path.with_suffix('.json')
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                original_filename = decrypted_json.get('metadata', {}).get('original_filename')
                if original_filename:
                    output_path = output_path / f"decrypted_{original_filename}"
                else:
                    output_path = output_path / f"{encrypted_file_path.stem}_decrypted.json"
        
        # For Microsoft Office files, use the file converter
        if file_type in ['word', 'excel', 'powerpoint']:
            try:
                output_path = self.file_converter.convert_from_json(decrypted_json, output_path)
            except Exception as e:
                self.audit_logger.log_event(
                    "FILE_CONVERT_ERROR",
                    "FAILURE",
                    "authenticated_user",
                    details=f"Error converting from JSON to {file_type}: {str(e)}"
                )
                # Fallback: save the JSON content
                json_output_path = output_path.with_suffix('.json')
                with open(json_output_path, 'w') as f:
                    json.dump(decrypted_json, f, indent=2)
                self.audit_logger.log_event(
                    "FILE_FALLBACK_SAVE",
                    "SUCCESS",
                    "authenticated_user",
                    details=f"Saved content as JSON instead: {json_output_path}"
                )
                return str(json_output_path)
        else:
            # For regular JSON, just save the content
            with open(output_path, 'w') as f:
                if 'content' in decrypted_json:
                    json.dump(decrypted_json['content'], f, indent=2)
                else:
                    json.dump(decrypted_json, f, indent=2)
        
        self.audit_logger.log_event(
            "FILE_DECRYPT",
            "SUCCESS",
            "authenticated_user",
            details=f"Decrypted {file_type} file: {encrypted_file_path.name} -> {output_path}"
        )
        
        return str(output_path)
    
    def get_audit_log_path(self) -> str:
        """Get the path to the audit log file."""
        return str(self.logs_dir / "access.log")


def main():
    """Command line interface for the encryption system."""
    parser = argparse.ArgumentParser(description="RSA-TOTP Hybrid Encryption System")
    
    # Setup command groups
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize the system')
    init_parser.add_argument('--issuer', required=True, help='Issuer name for TOTP')
    init_parser.add_argument('--user', required=True, help='User email for TOTP')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file (JSON or Microsoft Office)')
    encrypt_parser.add_argument('input', help='Input file path')
    encrypt_parser.add_argument('--output', help='Output encrypted file path')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt an encrypted file')
    decrypt_parser.add_argument('input', help='Input encrypted file path')
    decrypt_parser.add_argument('--output', help='Output decrypted file path')
    decrypt_parser.add_argument('--totp', required=True, help='TOTP code for authentication')
    
    # Audit command
    audit_parser = subparsers.add_parser('audit', help='View audit logs')
    audit_parser.add_argument('--verify', action='store_true', help='Verify log integrity')
    
    args = parser.parse_args()
    
    # Initialize the crypto system with the home directory structure
    crypto = RSATOTPCrypto()
    
    if args.command == 'init':
        qr_path = crypto.initialize_system(args.issuer, args.user)
        print(f"System initialized. TOTP QR code saved to: {qr_path}")
        print("Scan this QR code with your authenticator app to set up TOTP.")
        
    elif args.command == 'encrypt':
        try:
            output_path = crypto.encrypt_file(args.input, args.output)
            print(f"File encrypted and saved to: {output_path}")
        except ValueError as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
            
    elif args.command == 'decrypt':
        try:
            output_path = crypto.decrypt_file(args.input, args.totp, args.output)
            if output_path:
                print(f"File decrypted and saved to: {output_path}")
            else:
                print("Decryption failed. Invalid TOTP code.")
                sys.exit(1)
        except ValueError as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
            
    elif args.command == 'audit':
        audit_logger = AuditLogger(crypto.get_audit_log_path())
        logs = audit_logger.get_access_history()
        
        print(f"\nAudit Log ({len(logs)} entries):")
        print("=" * 80)
        
        for log in logs:
            timestamp = log.get("timestamp", "Unknown")
            event = log.get("event", "Unknown")
            status = log.get("status", "Unknown")
            actor = log.get("actor", {}).get("user_id", "Unknown")
            
            print(f"[{timestamp}] {event} - {status}")
            print(f"  Actor: {actor}")
            if log.get("details"):
                print(f"  Details: {log.get('details')}")
            print()
            
        if args.verify:
            integrity = audit_logger.verify_log_integrity()
            if integrity:
                print("Log integrity verification: PASSED")
            else:
                print("Log integrity verification: FAILED (possible tampering)")
                
    else:
        parser.print_help()
        

if __name__ == "__main__":
    main()
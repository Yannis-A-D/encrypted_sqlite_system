import os
import unittest
import base64
import json
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.cli import cmd_shell, main
from src import (
    kv_set, kv_get, kv_delete, get_db_connection, set_indexed_fields
)
from src.database import ROOT_DIR, set_cipher_key

class TestCLIShell(unittest.TestCase):
    def setUp(self):
        # Save key file and config
        self.key_file = ROOT_DIR / "secret.key"
        self.backup_key = None
        if self.key_file.exists():
            self.backup_key = self.key_file.read_text().strip()

        # Generate standard key for GCM
        raw_key_bytes = AESGCM.generate_key(bit_length=256)
        self.test_key = base64.urlsafe_b64encode(raw_key_bytes).decode("utf-8")
        self.key_file.write_text(self.test_key)
        set_cipher_key(self.test_key)

        # Clear tables
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM kv_store")
            conn.execute("DELETE FROM blind_indexes")

        set_indexed_fields(["level"])

    def tearDown(self):
        # Restore backup key
        if self.backup_key:
            self.key_file.write_text(self.backup_key)
            set_cipher_key(self.backup_key)
        elif self.key_file.exists():
            self.key_file.unlink()

        set_indexed_fields([])

    @patch("builtins.input")
    @patch("builtins.print")
    def test_cli_shell_full_lifecycle(self, mock_print, mock_input):
        """Test the interactive REPL shell by simulating a sequence of user inputs."""
        # Sequence of interactive inputs:
        # 1. help - print help message
        # 2. set a new key
        # 3. get the key to verify
        # 4. keys command to list
        # 5. find by index
        # 6. delete the key
        # 7. exit the shell
        inputs = [
            "help",
            "set user_1.json '{\"username\": \"Yannis\", \"level\": 99}'",
            "get user_1.json",
            "keys",
            "find level 99",
            "delete user_1.json",
            "get user_1.json",
            "exit"
        ]
        mock_input.side_effect = inputs

        # Enter shell
        cmd_shell(None)

        # Verify key was written and then deleted via Python API directly
        # since it runs against the same test database connection
        # The REPL ran all commands sequentially.
        
        # Let's inspect the printed output calls to assert behavior
        printed_texts = [call[0][0] for call in mock_print.call_args_list if call[0]]
        
        # Verify help printed
        self.assertTrue(any("Available Commands:" in text for text in printed_texts))
        
        # Verify success message for set printed
        self.assertTrue(any("Success: Key 'user_1.json' stored." in text for text in printed_texts))
        
        # Verify get returned Yannis
        self.assertTrue(any('"username": "Yannis"' in text for text in printed_texts))
        
        # Verify keys listed user_1.json
        self.assertTrue(any("user_1.json" in text for text in printed_texts))
        
        # Verify find by index found the record
        self.assertTrue(any('"level": 99' in text for text in printed_texts))
        
        # Verify delete print
        self.assertTrue(any("Success: Key 'user_1.json' deleted." in text for text in printed_texts))

        # Verify final get returned not found
        self.assertTrue(any("Key 'user_1.json' not found." in text for text in printed_texts))

        # Verify exit printed goodbye
        self.assertTrue(any("Goodbye!" in text for text in printed_texts))

if __name__ == "__main__":
    unittest.main()

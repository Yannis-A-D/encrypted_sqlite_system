"""
conftest.py — PyTest configuration and fixtures for Encrypted SQLite System tests.
"""

import os
import pytest
from pathlib import Path
from cryptography.fernet import Fernet

# Set test encryption key
TEST_KEY = Fernet.generate_key().decode()
os.environ["ENCRYPTION_KEY"] = TEST_KEY

import sys
pkg_root = Path(__file__).parent.parent
sys.path.insert(0, str(pkg_root))

from src.database import init_db, db_maintenance, DB_PATH
from src.cache import cache


@pytest.fixture(autouse=True)
def clean_environment():
    """Ensure clean state before each test."""
    cache.clear_l1()
    init_db()
    yield
    cache.clear_l1()

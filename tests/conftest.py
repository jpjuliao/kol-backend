import pytest
import os
from unittest.mock import patch
from dotenv import load_dotenv

# Load variables from .env file before any tests run
load_dotenv()

@pytest.fixture(autouse=True)
def mock_env_vars():
    """Mock environment variables for testing"""
    with patch.dict(os.environ, {
        'SUPABASE_URL': os.getenv('SUPABASE_URL'),
        'SUPABASE_ANON_KEY': os.getenv('SUPABASE_ANON_KEY'),
        'SUPABASE_JWT_SECRET': os.getenv('SUPABASE_JWT_SECRET')
    }):
        yield

@pytest.fixture
def mock_supabase_client():
    """Mock Supabase client for testing"""
    with patch('main.supabase') as mock_client:
        yield mock_client
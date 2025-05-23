import pytest
import os
from unittest.mock import patch

@pytest.fixture(autouse=True)
def mock_env_vars():
    """Mock environment variables for testing"""
    with patch.dict(os.environ, {
        'SUPABASE_URL': 'https://test-project.supabase.co',
        'SUPABASE_ANON_KEY': 'test-anon-key',
        'SUPABASE_JWT_SECRET': 'test-jwt-secret'
    }):
        yield

@pytest.fixture
def mock_supabase_client():
    """Mock Supabase client for testing"""
    with patch('main.supabase') as mock_client:
        yield mock_client
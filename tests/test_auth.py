import pytest
import httpx
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from main import app
import json

class TestAuth:
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def mock_user_data(self):
        """Mock user data for testing"""
        return {
            "id": "test-user-id-123",
            "email": "test@example.com",
            "created_at": "2024-01-01T00:00:00Z"
        }
    
    @pytest.fixture
    def mock_session_data(self):
        """Mock session data for testing"""
        return {
            "access_token": "mock-jwt-token-12345",
            "refresh_token": "mock-refresh-token",
            "expires_in": 3600,
            "token_type": "bearer"
        }

    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    @patch('main.supabase.auth.sign_in_with_password')
    def test_login_success(self, mock_sign_in, client, mock_user_data, mock_session_data):
        """Test successful login"""
        # Mock successful Supabase response
        mock_response = Mock()
        mock_response.user = Mock()
        mock_response.user.id = mock_user_data["id"]
        mock_response.user.email = mock_user_data["email"]
        mock_response.user.created_at = mock_user_data["created_at"]
        mock_response.session = Mock()
        mock_response.session.access_token = mock_session_data["access_token"]
        
        mock_sign_in.return_value = mock_response
        
        # Test login
        login_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }
        
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "access_token" in data
        assert "token_type" in data
        assert "user" in data
        assert data["token_type"] == "bearer"
        assert data["access_token"] == mock_session_data["access_token"]
        
        # Verify user data
        user = data["user"]
        assert user["id"] == mock_user_data["id"]
        assert user["email"] == mock_user_data["email"]
        assert user["created_at"] == mock_user_data["created_at"]
        
        # Verify Supabase was called correctly
        mock_sign_in.assert_called_once_with({
            "email": "test@example.com",
            "password": "testpassword123"
        })

    @patch('main.supabase.auth.sign_in_with_password')
    def test_login_invalid_credentials(self, mock_sign_in, client):
        """Test login with invalid credentials"""
        # Mock failed Supabase response
        mock_response = Mock()
        mock_response.user = None
        mock_sign_in.return_value = mock_response
        
        login_data = {
            "email": "test@example.com",
            "password": "wrongpassword"
        }
        
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 401
        data = response.json()
        assert data["detail"] == "Invalid email or password"

    @patch('main.supabase.auth.sign_in_with_password')
    def test_login_supabase_error(self, mock_sign_in, client):
        """Test login when Supabase returns an error"""
        # Mock Supabase exception
        mock_sign_in.side_effect = Exception("Invalid login credentials")
        
        login_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }
        
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 401
        data = response.json()
        assert data["detail"] == "Invalid email or password"

    @patch('main.supabase.auth.sign_in_with_password')
    def test_login_server_error(self, mock_sign_in, client):
        """Test login with server error"""
        # Mock generic exception
        mock_sign_in.side_effect = Exception("Server connection error")
        
        login_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }
        
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 500
        data = response.json()
        assert data["detail"] == "Authentication failed"

    def test_login_invalid_email_format(self, client):
        """Test login with invalid email format"""
        login_data = {
            "email": "invalid-email",
            "password": "testpassword123"
        }
        
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data

    def test_login_missing_password(self, client):
        """Test login with missing password"""
        login_data = {
            "email": "test@example.com"
        }
        
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data

    def test_login_missing_email(self, client):
        """Test login with missing email"""
        login_data = {
            "password": "testpassword123"
        }
        
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data

    def test_login_empty_request_body(self, client):
        """Test login with empty request body"""
        response = client.post("/auth/login", json={})
        
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data

    @patch('main.supabase.auth.get_user')
    def test_get_current_user_success(self, mock_get_user, client, mock_user_data):
        """Test getting current user with valid token"""
        # Mock successful user retrieval
        mock_response = Mock()
        mock_response.user = Mock()
        mock_response.user.id = mock_user_data["id"]
        mock_response.user.email = mock_user_data["email"]
        mock_response.user.created_at = mock_user_data["created_at"]
        
        mock_get_user.return_value = mock_response
        
        headers = {"Authorization": "Bearer valid-token"}
        response = client.get("/auth/me", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["id"] == mock_user_data["id"]
        assert data["email"] == mock_user_data["email"]
        assert data["created_at"] == mock_user_data["created_at"]

    @patch('main.supabase.auth.get_user')
    def test_get_current_user_invalid_token(self, mock_get_user, client):
        """Test getting current user with invalid token"""
        # Mock failed user retrieval
        mock_response = Mock()
        mock_response.user = None
        mock_get_user.return_value = mock_response
        
        headers = {"Authorization": "Bearer invalid-token"}
        response = client.get("/auth/me", headers=headers)
        
        assert response.status_code == 401
        data = response.json()
        assert data["detail"] == "Invalid authentication credentials"

    def test_get_current_user_no_token(self, client):
        """Test getting current user without token"""
        response = client.get("/auth/me")
        
        assert response.status_code == 403
        data = response.json()
        assert data["detail"] == "Not authenticated"

    @patch('main.supabase.auth.get_user')
    @patch('main.supabase.auth.sign_out')
    def test_logout_success(self, mock_sign_out, mock_get_user, client, mock_user_data):
        """Test successful logout"""
        # Mock valid user for authentication
        mock_response = Mock()
        mock_response.user = Mock()
        mock_response.user.id = mock_user_data["id"]
        mock_response.user.email = mock_user_data["email"]
        mock_response.user.created_at = mock_user_data["created_at"]
        mock_get_user.return_value = mock_response
        
        headers = {"Authorization": "Bearer valid-token"}
        response = client.post("/auth/logout", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Successfully logged out"
        
        # Verify sign_out was called
        mock_sign_out.assert_called_once()

    @patch('main.supabase.auth.get_user')
    def test_protected_route_success(self, mock_get_user, client, mock_user_data):
        """Test protected route with valid token"""
        # Mock valid user
        mock_response = Mock()
        mock_response.user = Mock()
        mock_response.user.id = mock_user_data["id"]
        mock_response.user.email = mock_user_data["email"]
        mock_response.user.created_at = mock_user_data["created_at"]
        mock_get_user.return_value = mock_response
        
        headers = {"Authorization": "Bearer valid-token"}
        response = client.get("/protected", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "message" in data
        assert mock_user_data["email"] in data["message"]
        assert data["user_id"] == mock_user_data["id"]

    def test_protected_route_no_token(self, client):
        """Test protected route without token"""
        response = client.get("/protected")
        
        assert response.status_code == 403
        data = response.json()
        assert data["detail"] == "Not authenticated"

class TestAuthIntegration:
    """Integration tests for authentication flow"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)

    def test_full_auth_flow_mock(self, client):
        """Test complete authentication flow (mocked)"""
        with patch('main.supabase.auth.sign_in_with_password') as mock_sign_in, \
             patch('main.supabase.auth.get_user') as mock_get_user, \
             patch('main.supabase.auth.sign_out') as mock_sign_out:
            
            # Mock data
            mock_user = Mock()
            mock_user.id = "test-id"
            mock_user.email = "test@example.com"
            mock_user.created_at = "2024-01-01T00:00:00Z"
            
            mock_session = Mock()
            mock_session.access_token = "test-token"
            
            # Mock login response
            mock_login_response = Mock()
            mock_login_response.user = mock_user
            mock_login_response.session = mock_session
            mock_sign_in.return_value = mock_login_response
            
            # Mock get_user response
            mock_user_response = Mock()
            mock_user_response.user = mock_user
            mock_get_user.return_value = mock_user_response
            
            # 1. Login
            login_data = {"email": "test@example.com", "password": "password123"}
            login_response = client.post("/auth/login", json=login_data)
            assert login_response.status_code == 200
            
            token = login_response.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            
            # 2. Access protected route
            protected_response = client.get("/protected", headers=headers)
            assert protected_response.status_code == 200
            
            # 3. Get user info
            user_response = client.get("/auth/me", headers=headers)
            assert user_response.status_code == 200
            
            # 4. Logout
            logout_response = client.post("/auth/logout", headers=headers)
            assert logout_response.status_code == 200

class TestAuthValidation:
    """Test input validation and edge cases"""
    
    @pytest.fixture
    def client(self):
        return TestClient(app)
    
    @pytest.mark.parametrize("email,password,expected_status", [
        ("", "password123", 422),  # Empty email
        ("test@example.com", "", 422),  # Empty password
        ("invalid-email", "password123", 422),  # Invalid email format
        ("test@", "password123", 422),  # Incomplete email
        ("@example.com", "password123", 422),  # Missing local part
        ("test@example", "password123", 422),  # Missing TLD
    ])
    def test_login_validation(self, client, email, password, expected_status):
        """Test various validation scenarios"""
        login_data = {"email": email, "password": password}
        response = client.post("/auth/login", json=login_data)
        assert response.status_code == expected_status

    def test_login_sql_injection_attempt(self, client):
        """Test that SQL injection attempts are handled safely"""
        with patch('main.supabase.auth.sign_in_with_password') as mock_sign_in:
            mock_sign_in.side_effect = Exception("Invalid login credentials")
            
            login_data = {
                "email": "admin@example.com'; DROP TABLE users; --",
                "password": "password"
            }
            
            response = client.post("/auth/login", json=login_data)
            assert response.status_code == 401
            
            # Verify the malicious input was passed safely to Supabase
            mock_sign_in.assert_called_once()

if __name__ == "__main__":
    pytest.main(["-v", "tests/test_auth.py"])
    
"""
# This file makes the tests directory a Python package
"""

"""
const API_BASE = '';
let authToken = localStorage.getItem('authToken');

// Check if user is already logged in
if (authToken) {
    checkAuthStatus();
}

// Login form handler
document.getElementById('login').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const loginBtn = document.getElementById('loginBtn');
    const errorDiv = document.getElementById('loginError');
    
    loginBtn.disabled = true;
    loginBtn.textContent = 'Logging in...';
    errorDiv.textContent = '';
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            authToken = data.access_token;
            localStorage.setItem('authToken', authToken);
            showUserDashboard(data.user);
        } else {
            errorDiv.textContent = data.detail || 'Login failed';
        }
    } catch (error) {
        errorDiv.textContent = 'Network error. Please try again.';
    }
    
    loginBtn.disabled = false;
    loginBtn.textContent = 'Login';
});

// Logout handler
document.getElementById('logoutBtn').addEventListener('click', async () => {
    try {
        await fetch(`${API_BASE}/auth/logout`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
    } catch (error) {
        console.error('Logout error:', error);
    }
    
    localStorage.removeItem('authToken');
    authToken = null;
    showLoginForm();
});

async function checkAuthStatus() {
    try {
        const response = await fetch(`${API_BASE}/auth/me`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            const user = await response.json();
            showUserDashboard(user);
        } else {
            localStorage.removeItem('authToken');
            authToken = null;
            showLoginForm();
        }
    } catch (error) {
        localStorage.removeItem('authToken');
        authToken = null;
        showLoginForm();
    }
}

function showLoginForm() {
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('userDashboard').style.display = 'none';
}

function showUserDashboard(user) {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('userDashboard').style.display = 'block';
    
    document.getElementById('userInfo').innerHTML = `
        <h3>User Information</h3>
        <p><strong>ID:</strong> ${user.id}</p>
        <p><strong>Email:</strong> ${user.email}</p>
        <p><strong>Created:</strong> ${new Date(user.created_at).toLocaleDateString()}</p>
    `;
}
"""

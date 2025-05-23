# KOL Backend

An API application for User authentication (login only with email and password)

## Infrastructure

Infrastructure refers to the foundational technologies and services that support the application.  
For this project, the infrastructure includes:

* **FastAPI** – Python web framework for building the API.
* **Supabase Auth** – Provides user authentication and JWT issuance.
* **Supabase Database** – PostgreSQL database for storing application data.

## Architecture

Architecture describes the overall design and structure of the application, including how components interact and how data flows.  
For this project:

* The API is built using FastAPI, exposing endpoints for user authentication.
* Authentication and user management are handled by Supabase Auth, which issues JWTs for secure access.
* Application data is stored and managed in a Supabase PostgreSQL database.
* The backend communicates with Supabase services via RESTful APIs and direct database queries.

## API Endpoints

* POST /auth/login - Login with email/password
* GET /auth/me - Get current user (requires auth)
* POST /auth/logout - Logout user (requires auth)
* GET /protected - Protected route example (requires auth)
* GET /health - Health check

### `POST /auth/login`

Authenticate a user with email and password.  

**Request body:**  

```json
{
  "email": "user@example.com",
  "password": "yourpassword"
}
```

**Response:**  

* `200 OK` with JWT token on success
* `401 Unauthorized` on failure

### `GET /auth/me`

Get the authenticated user's profile.  

**Headers:**  

* `Authorization: Bearer <JWT token>`

**Response:**  

* `200 OK` with user profile data
* `401 Unauthorized` if not authenticated

## Backend Features (FastAPI)

Login endpoint (/auth/login) - Authenticates users with email/password
User profile endpoint (/auth/me) - Gets current user info
Logout endpoint (/auth/logout) - Signs out users
Protected route example (/protected) - Demonstrates JWT authentication
JWT token verification - Middleware for protecting routes
CORS support - For frontend integration

## Frontend Features

Clean login interface - Modern, responsive design
User dashboard - Shows user information after login
Token persistence - Stores JWT in localStorage
Error handling - User-friendly error messages
Auto-login - Remembers logged-in users

## Setup Instructions

### Install dependencies

```bash
pip install fastapi uvicorn supabase python-jose python-multipart pydantic python-dotenv
```

### Set up Supabase

* Create a Supabase project at supabase.com
* Enable Email authentication in Authentication settings
* Create a .env file with your Supabase credentials:

```env
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_JWT_SECRET=your-jwt-secret
```

### Run the application

```bash
uvicorn main:app --reload
```

### Access the app

API: <http://localhost:8000>
Frontend: <http://localhost:8000>
API Docs: <http://localhost:8000/docs>

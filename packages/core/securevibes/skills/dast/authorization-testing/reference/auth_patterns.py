#!/usr/bin/env python3
"""
Reusable authentication patterns for authorization testing.

These are reference implementations to illustrate common authentication
patterns. Adapt them to your specific application's auth mechanism.

Usage:
    from auth_patterns import session_based_auth, jwt_bearer_auth, api_key_auth
    
    # Choose appropriate auth method
    session = session_based_auth(target_url, username, password)
    # OR
    headers = jwt_bearer_auth(target_url, username, password)
    # OR
    headers = api_key_auth(api_key)
"""

import requests
from typing import Dict, Optional


def session_based_auth(
    target_url: str,
    username: str,
    password: str,
    login_endpoint: str = "/login"
) -> requests.Session:
    """
    Session-based authentication (Flask, Express, Django).
    
    Args:
        target_url: Base URL of target application
        username: User's username or email
        password: User's password
        login_endpoint: Login endpoint path (default: /login)
    
    Returns:
        requests.Session object with authenticated session cookie
    
    Example:
        session = session_based_auth("http://localhost:5000", "user1", "pass123")
        response = session.get(f"{target_url}/api/profile")
    """
    session = requests.Session()
    
    # Attempt login - adapt data format to your app
    login_url = f"{target_url}{login_endpoint}"
    resp = session.post(
        login_url,
        data={"username": username, "password": password}
    )
    
    # Session cookie stored automatically in session object
    if resp.status_code not in [200, 302]:
        raise ValueError(f"Authentication failed: {resp.status_code}")
    
    return session


def jwt_bearer_auth(
    target_url: str,
    username: str,
    password: str,
    auth_endpoint: str = "/api/auth/login",
    token_key: str = "access_token"
) -> Dict[str, str]:
    """
    JWT Bearer token authentication (REST APIs).
    
    Args:
        target_url: Base URL of target application
        username: User's username or email
        password: User's password
        auth_endpoint: Authentication endpoint path (default: /api/auth/login)
        token_key: JSON key for access token (default: "access_token")
    
    Returns:
        Dictionary with Authorization header
    
    Example:
        headers = jwt_bearer_auth("http://localhost:5000", "user1", "pass123")
        response = requests.get(f"{target_url}/api/profile", headers=headers)
    """
    auth_url = f"{target_url}{auth_endpoint}"
    
    # Attempt authentication - adapt JSON format to your app
    resp = requests.post(
        auth_url,
        json={"username": username, "password": password}
    )
    
    if resp.status_code != 200:
        raise ValueError(f"Authentication failed: {resp.status_code}")
    
    # Extract token from response
    token = resp.json().get(token_key)
    if not token:
        raise ValueError(f"Token key '{token_key}' not found in response")
    
    return {"Authorization": f"Bearer {token}"}


def api_key_auth(
    api_key: str,
    header_name: str = "X-API-Key"
) -> Dict[str, str]:
    """
    API key authentication.
    
    Args:
        api_key: API key for the user
        header_name: Header name for API key (default: "X-API-Key")
    
    Returns:
        Dictionary with API key header
    
    Example:
        headers = api_key_auth("abc123xyz")
        response = requests.get(f"{target_url}/api/profile", headers=headers)
    """
    return {header_name: api_key}


def oauth2_token_auth(
    access_token: str,
    token_type: str = "Bearer"
) -> Dict[str, str]:
    """
    OAuth2 access token authentication.
    
    Args:
        access_token: OAuth2 access token
        token_type: Token type (default: "Bearer")
    
    Returns:
        Dictionary with Authorization header
    
    Example:
        headers = oauth2_token_auth("eyJhbGc...")
        response = requests.get(f"{target_url}/api/profile", headers=headers)
    """
    return {"Authorization": f"{token_type} {access_token}"}


def basic_auth(
    username: str,
    password: str
) -> Dict[str, str]:
    """
    HTTP Basic authentication.
    
    Args:
        username: User's username
        password: User's password
    
    Returns:
        Dictionary with Authorization header
    
    Example:
        headers = basic_auth("user1", "pass123")
        response = requests.get(f"{target_url}/api/profile", headers=headers)
    """
    import base64
    
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode()).decode()
    
    return {"Authorization": f"Basic {encoded}"}


# Helper function to automatically detect and use appropriate auth
def auto_auth(
    target_url: str,
    credentials: Dict,
    auth_type: Optional[str] = None
) -> tuple:
    """
    Automatically authenticate based on auth type.
    
    Args:
        target_url: Base URL of target application
        credentials: Dictionary with auth credentials
        auth_type: Type of auth ("session", "jwt", "api_key", "basic")
                   If None, attempts to detect from credentials keys
    
    Returns:
        Tuple of (session_or_headers, auth_type_used)
    
    Example:
        creds = {"username": "user1", "password": "pass123"}
        session, auth_type = auto_auth("http://localhost:5000", creds)
    """
    if auth_type is None:
        # Auto-detect based on credential keys
        if "api_key" in credentials:
            auth_type = "api_key"
        elif "access_token" in credentials:
            auth_type = "oauth2"
        elif "username" in credentials and "password" in credentials:
            # Default to session-based for username/password
            auth_type = "session"
        else:
            raise ValueError("Cannot auto-detect auth type from credentials")
    
    if auth_type == "session":
        session = session_based_auth(
            target_url,
            credentials["username"],
            credentials["password"]
        )
        return session, "session"
    
    elif auth_type == "jwt":
        headers = jwt_bearer_auth(
            target_url,
            credentials["username"],
            credentials["password"]
        )
        return headers, "jwt"
    
    elif auth_type == "api_key":
        headers = api_key_auth(credentials["api_key"])
        return headers, "api_key"
    
    elif auth_type == "oauth2":
        headers = oauth2_token_auth(credentials["access_token"])
        return headers, "oauth2"
    
    elif auth_type == "basic":
        headers = basic_auth(
            credentials["username"],
            credentials["password"]
        )
        return headers, "basic"
    
    else:
        raise ValueError(f"Unknown auth type: {auth_type}")

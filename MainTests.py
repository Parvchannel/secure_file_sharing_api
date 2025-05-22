import os
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "message" in response.json()

def test_register_user():
    response = client.post("/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "role": "client"
    })
    assert response.status_code in [200, 409]  # 409 if user already exists

def test_login_user():
    response = client.post("/auth/login", json={
        "username": "testuser",
        "password": "password123"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_upload_file():
    # First, login to get the token
    login_response = client.post("/auth/login", json={
        "username": "testuser",
        "password": "password123"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Upload a file
    file_path = "tests/testfile.txt"
    with open(file_path, "w") as f:
        f.write("This is a test file.")
    with open(file_path, "rb") as file:
        response = client.post("/ops/upload", files={"file": file}, headers=headers)
    os.remove(file_path)
    assert response.status_code == 200
    assert "File uploaded successfully" in response.json()["message"]

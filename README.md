# Secure File Sharing System

A secure file sharing system built with **FastAPI**, **MongoDB**, and **Docker**, supporting user authentication, role-based access (`ops` and `client`), file uploads, downloads, and email verification.

---

##  Features

- User Registration with Email Verification  
- Secure Login with JWT  
- Role-based Access Control  
- File Upload & Download APIs  
- MongoDB Integration  
- Dockerized for easy deployment  
- REST API with automatic documentation via Swagger  

---

##  Tech Stack

- **Backend**: FastAPI, Python 3.11+
- **Database**: MongoDB
- **Auth**: JWT, Bcrypt
- **Email**: SMTP (e.g., Gmail)
- **Containerization**: Docker, Docker Compose

---

##  Local Development Setup

### 1. **Clone the Repository**

bash

git clone https://github.com/yourusername/secure-file-sharing-api.git
cd secure-file-sharing-api

2. Start MongoDB via Docker
bash
Copy
Edit
docker run -d -p 27017:27017 --name mongo mongo

3. Install Python Dependencies
bash
Copy
Edit
pip install -r requirements.txt

4. Run the FastAPI App
bash
Copy
Edit
uvicorn main:app --reload

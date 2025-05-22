

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os, shutil, uuid

app = FastAPI()

# Config
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
UPLOAD_DIR = "./uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client.secure_share

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


class User(BaseModel):
    email: EmailStr
    password: str
    role: str 

class FileMetadata(BaseModel):
    id: str
    filename: str
    uploaded_by: str
    upload_time: datetime


def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = await db.users.find_one({"email": payload.get("sub")})
        if user:
            return user
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid authentication")
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/signup")
async def signup(user: User):
    if await db.users.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(user.password)
    user_data = {"email": user.email, "password": hashed, "role": user.role, "verified": False}
    await db.users.insert_one(user_data)
    token = create_access_token({"sub": user.email}, timedelta(minutes=10))
    return {"secure_url": f"/verify-email/{token}", "message": "Verification email sent"}

@app.get("/verify-email/{token}")
async def verify_email(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        await db.users.update_one({"email": email}, {"$set": {"verified": True}})
        return {"message": "Email verified successfully"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user['password']):
        raise HTTPException(status_code=401, detail="Incorrect credentials")
    if not user.get("verified"):
        raise HTTPException(status_code=403, detail="Email not verified")
    access_token = create_access_token(data={"sub": user['email']}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...), current_user=Depends(get_current_user)):
    if current_user['role'] != 'ops':
        raise HTTPException(status_code=403, detail="Only Ops user can upload")
    ext = file.filename.split('.')[-1].lower()
    if ext not in ["pptx", "docx", "xlsx"]:
        raise HTTPException(status_code=400, detail="Invalid file type")
    file_id = str(uuid.uuid4())
    path = os.path.join(UPLOAD_DIR, file_id + "-" + file.filename)
    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    await db.files.insert_one({"id": file_id, "filename": file.filename, "uploaded_by": current_user['email'], "upload_time": datetime.utcnow()})
    return {"message": "File uploaded successfully", "file_id": file_id}

@app.get("/files")
async def list_files(current_user=Depends(get_current_user)):
    if current_user['role'] != 'client':
        raise HTTPException(status_code=403, detail="Only Client user can view files")
    files = await db.files.find().to_list(None)
    return [{"id": f['id'], "filename": f['filename']} for f in files]


@app.get("/download-file/{file_id}")
async def get_download_link(file_id: str, current_user=Depends(get_current_user)):
    if current_user['role'] != 'client':
        raise HTTPException(status_code=403, detail="Only Client user can download files")
    token = create_access_token({"file_id": file_id, "user": current_user['email']}, timedelta(minutes=10))
    return {"download-link": f"/secure-download/{token}", "message": "success"}


@app.get("/secure-download/{token}")
async def secure_download(token: str, current_user=Depends(get_current_user)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("user") != current_user['email']:
            raise HTTPException(status_code=403, detail="This link is not for you")
        file_entry = await db.files.find_one({"id": payload.get("file_id")})
        if not file_entry:
            raise HTTPException(status_code=404, detail="File not found")
        path = os.path.join(UPLOAD_DIR, payload.get("file_id") + "-" + file_entry['filename'])
        return FileResponse(path, media_type='application/octet-stream', filename=file_entry['filename'])
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

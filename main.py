from fastapi import FastAPI, Depends, Form, UploadFile, File ,HTTPException
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from datetime import datetime, timedelta
from typing import Optional , Literal
import os, urllib.parse, bcrypt, jwt 

app = FastAPI()

# === Database setup ===
username = "postgres"
password = 'RGS@123'
encoded_password = urllib.parse.quote_plus(password)
DB_URL = f"postgresql://{username}:{encoded_password}@localhost:5432/michelanglo_db"

engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# === Static media dir ===
MEDIA_DIR = "media"
os.makedirs(MEDIA_DIR, exist_ok=True)
app.mount("/media", StaticFiles(directory="media"), name="media")

# === Security ===
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# === DB Models ===
class User(Base):
    __tablename__ = "users" 
    id = Column(Integer, primary_key=True, index=True)
    user_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    mobile = Column(String, nullable=False)  
    country_code = Column(String, nullable=False)
    otp = Column(String, nullable=True)
    otp_expiration = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==== USER REGISTER ====#
@app.post("/Register")
def register_user(
    user_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == email).first():
        return {"status": "0", "message": "User Email Already Exists", "result": {}}
    hashed_password = hash_password(password)
    db_user = User(user_name=user_name, email=email, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"status": "1", "message": "User Registration Successfully!", "id": db_user.id}
# ==== USER LOGIN ====#
@app.post("/Login")
def login(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email.strip()).first()
    if not user or not verify_password(password, user.password):
        return {"status": "0", "message": "Invalid credentials", "result": {}}
    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {
        "status": "1",
        "message": "Login Successful",
        "result": {
            "id": user.id,
            "user_name": user.user_name,
            "email": user.email,
            "password": user.password,
            "mobile": user.mobile,
            "created_at": str(user.created_at),
            "token": access_token  } }
# ==== ADD USER  MOBILE_NUMBER ====#    
@app.post("/send_otp")
def send_otp(
    id: int = Form(...),
    mobile: str = Form(...),
    country_code: Optional[str] = Form(None),
    db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == id).first()
    if not user:
        return {"status": "0", "message": "User Not Found", "result": {}}
    user.mobile = mobile
    if country_code is not None:
        user.country_code = country_code
    otp = "9999"  
    user.otp = otp
    user.otp_expiration = datetime.utcnow() + timedelta(minutes=10)
    db.commit()
    return {
        "status": "1",
        "message": f"OTP sent to {country_code or ''}{mobile}",
        "result": {"otp": otp} }
# === VERIFY -- OTP === #    
@app.post("/verify-otp")
def verify_otp(
    mobile: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db)):
    user = db.query(User).filter(User.mobile == mobile).first()
    if not user :
        return {"status": "0", "message": "Invalid mobile number", "results": {}}
    elif user.otp != otp:
        return {"status": "0", "message": "Invalid  OTP", "results": {}}
    return {
        "status": "1",
        "message": "OTP Verified",
        "result": {
            "id": user.id,
            "user_name": user.user_name,
            "email": user.email,
            "mobile": user.mobile,
            "created_at": str(user.created_at),
            "otp": user.otp  }  }
# === FORGOT PASSWORD === #
@app.post("/forgot_password")
def forgot_password(
    method: Literal["email", "phone"] = Form(...),
    identifier: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.email == identifier if method == "email" else User.mobile == identifier).first()
    if not user:
        return {"status": "0", "message": "User not found", "result": {}}
    otp = '9999'
    user.otp = otp
    user.otp_expiration = datetime.utcnow() + timedelta(minutes=10)
    db.commit()
    contact = user.email if method == "email" else user.mobile
    print(f"Sending OTP to {method}: {contact} - OTP: {otp}")
    return {
        "status": "1",
        "message": f"OTP sent to your {method}",
        "result": {
            "contact": contact,
            "masked": mask_email(contact) if method == "email" else mask_phone(contact)  }   }
    
def mask_email(email):
    local, domain = email.split("@")
    return f"{local[:3]}{'*'*(len(local)-3)}@{domain}"

def mask_phone(phone):
    return f"{'*'*6}{phone[-4:]}"

# === VERIFY FORGOT PASSWORD OTP === #
@app.post("/verify_porgot_password_otp")
def verify_otp(
    method: Literal["email", "phone"] = Form(...),
    identifier: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.email == identifier if method == "email" else User.mobile == identifier ).first()
    if not user or user.otp != otp:
        return {"status": "0", "message": "Invalid OTP", "result": {}}
    otp_expiration = datetime.fromisoformat(user.otp_expiration)
    if otp_expiration < datetime.utcnow():
        return {"status": "0", "message": "OTP expired", "result": {}}
    return {"status": "1", "message": "OTP verified", "result": {"user_id": user.id}}

# === RESET PASSWORD === #
@app.post("/reset-password")
def reset_password(
    user_id: int = Form(...),  # or get from token/session in production
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if new_password != confirm_password:
        return {"status":"0","message":"password and confirm password do not match"}
    user.password = hash_password(new_password)
    db.commit()
    return {"status": "1", "message": "Password reset successfully"}
# ===  Delete User === #
@app.post("/Delete")
def delete_user(
    user_id: int = Form(...),
    db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"status": "0", "message": "User not found"}
    db.delete(user)
    db.commit()
    return {"status": "1", "message": f"User with ID {user_id} deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

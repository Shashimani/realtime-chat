from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

app = FastAPI()

# ─── CONFIG ───────────────────────────────────────────────
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ─── PASSWORD HASHING ─────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ─── IN-MEMORY USER DATABASE ──────────────────────────────
# { username: { "username", "email", "hashed_password" } }
users_db = {}

# ─── ACTIVE WEBSOCKET CLIENTS ─────────────────────────────
clients = {}  # { username: websocket }


# ─── MODELS ───────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


# ─── HELPERS ──────────────────────────────────────────────
def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ─── ROUTES ───────────────────────────────────────────────
@app.get("/")
def get():
    with open("index.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.post("/register")
def register(req: RegisterRequest):
    # Check username
    if req.username in users_db:
        raise HTTPException(status_code=400, detail="Username already taken")
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")

    # Check email uniqueness
    for user in users_db.values():
        if user["email"] == req.email:
            raise HTTPException(status_code=400, detail="Email already registered")

    # Check password
    if len(req.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    users_db[req.username] = {
        "username": req.username,
        "email": req.email,
        "hashed_password": hash_password(req.password)
    }
    return {"message": "Registered successfully"}


@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Allow login with username OR email
    user = users_db.get(form_data.username)

    if not user:
        # Try finding by email
        for u in users_db.values():
            if u["email"] == form_data.username:
                user = u
                break

    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid username/email or password")

    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me")
def me(current_user: str = Depends(get_current_user)):
    user = users_db.get(current_user)
    return {"username": user["username"], "email": user["email"]}


# ─── BROADCAST USERS ──────────────────────────────────────
async def broadcast_users():
    user_list = "USERS:" + ",".join(clients.keys())
    for conn in clients.values():
        await conn.send_text(user_list)


# ─── WEBSOCKET ────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    # First message must be JWT token
    token = await websocket.receive_text()

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            await websocket.send_text("❌ Invalid token")
            await websocket.close()
            return
    except JWTError:
        await websocket.send_text("❌ Invalid token")
        await websocket.close()
        return

    clients[username] = websocket

    for conn in clients.values():
        await conn.send_text(f"🟢 {username} joined")

    await broadcast_users()

    try:
        while True:
            data = await websocket.receive_text()

            if "|" in data:
                to_user, message = data.split("|", 1)
                if to_user in clients:
                    await clients[to_user].send_text(f"💬 {username} (private): {message}")
                    await websocket.send_text(f"📤 You to {to_user}: {message}")
                else:
                    await websocket.send_text("❌ User not online")
            else:
                for conn in clients.values():
                    await conn.send_text(f"{username}: {data}")

    except WebSocketDisconnect:
        del clients[username]
        for conn in clients.values():
            await conn.send_text(f"🔴 {username} left")
        await broadcast_users()

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import json

app = FastAPI()

# ─── CONFIG ───────────────────────────────────────────────
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ─── PASSWORD HASHING ─────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ─── IN-MEMORY DATABASES ──────────────────────────────────
users_db = {}
# { username: { "username", "email", "hashed_password" } }

friends_db = {}
# { username: set(friends) }

friend_requests_db = {}
# { username: set(pending_requests_from) }

clients = {}
# { username: websocket }


# ─── MODELS ───────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class FriendRequest(BaseModel):
    to_username: str

class FriendAction(BaseModel):
    from_username: str
    action: str  # "accept" or "reject"


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

def are_friends(user1: str, user2: str) -> bool:
    return user2 in friends_db.get(user1, set())

def get_online_friends(username: str) -> list:
    return [u for u in friends_db.get(username, set()) if u in clients]

def get_pending_requests(username: str) -> list:
    return list(friend_requests_db.get(username, set()))

async def notify_user(username: str, message: dict):
    """Send a JSON notification to a connected user."""
    if username in clients:
        await clients[username].send_text(json.dumps(message))


# ─── AUTH ROUTES ──────────────────────────────────────────
@app.get("/")
def get():
    with open("index.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.post("/register")
def register(req: RegisterRequest):
    if req.username in users_db:
        raise HTTPException(status_code=400, detail="Username already taken")
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    for user in users_db.values():
        if user["email"] == req.email:
            raise HTTPException(status_code=400, detail="Email already registered")
    if len(req.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    users_db[req.username] = {
        "username": req.username,
        "email": req.email,
        "hashed_password": hash_password(req.password)
    }
    friends_db[req.username] = set()
    friend_requests_db[req.username] = set()
    return {"message": "Registered successfully"}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user:
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


# ─── FRIEND ROUTES ────────────────────────────────────────
@app.post("/friend/request")
async def send_friend_request(req: FriendRequest, current_user: str = Depends(get_current_user)):
    to = req.to_username

    if to not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    if to == current_user:
        raise HTTPException(status_code=400, detail="Cannot add yourself")
    if are_friends(current_user, to):
        raise HTTPException(status_code=400, detail="Already friends")
    if current_user in friend_requests_db.get(to, set()):
        raise HTTPException(status_code=400, detail="Friend request already sent")

    # If they already sent us a request → auto accept
    if to in friend_requests_db.get(current_user, set()):
        friend_requests_db[current_user].discard(to)
        friends_db[current_user].add(to)
        friends_db[to].add(current_user)

        await notify_user(to, {
            "type": "friend_accepted",
            "from": current_user,
            "message": f"🤝 {current_user} is now your friend!"
        })
        await notify_user(current_user, {
            "type": "friend_accepted",
            "from": to,
            "message": f"🤝 {to} is now your friend!"
        })
        return {"message": "Friend request accepted automatically (they already requested you)"}

    friend_requests_db[to].add(current_user)

    # Notify recipient if online
    await notify_user(to, {
        "type": "friend_request",
        "from": current_user,
        "message": f"👋 {current_user} sent you a friend request"
    })

    return {"message": f"Friend request sent to {to}"}


@app.post("/friend/respond")
async def respond_friend_request(action: FriendAction, current_user: str = Depends(get_current_user)):
    from_user = action.from_username

    if from_user not in friend_requests_db.get(current_user, set()):
        raise HTTPException(status_code=400, detail="No friend request from this user")

    friend_requests_db[current_user].discard(from_user)

    if action.action == "accept":
        friends_db[current_user].add(from_user)
        friends_db[from_user].add(current_user)

        await notify_user(from_user, {
            "type": "friend_accepted",
            "from": current_user,
            "message": f"🤝 {current_user} accepted your friend request!"
        })
        await notify_user(current_user, {
            "type": "friend_accepted",
            "from": from_user,
            "message": f"🤝 You are now friends with {from_user}!"
        })
        return {"message": f"You are now friends with {from_user}"}

    elif action.action == "reject":
        await notify_user(from_user, {
            "type": "friend_rejected",
            "from": current_user,
            "message": f"❌ {current_user} declined your friend request."
        })
        return {"message": f"Friend request from {from_user} rejected"}

    raise HTTPException(status_code=400, detail="Invalid action")


@app.get("/friends")
def get_friends(current_user: str = Depends(get_current_user)):
    my_friends = list(friends_db.get(current_user, set()))
    online = get_online_friends(current_user)
    pending_in = list(friend_requests_db.get(current_user, set()))

    # Pending requests I sent
    pending_out = [
        u for u, reqs in friend_requests_db.items()
        if current_user in reqs
    ]

    return {
        "friends": my_friends,
        "online_friends": online,
        "pending_incoming": pending_in,
        "pending_outgoing": pending_out
    }


@app.get("/users/search")
def search_users(q: str, current_user: str = Depends(get_current_user)):
    results = []
    for username in users_db:
        if username == current_user:
            continue
        if q.lower() in username.lower():
            results.append({
                "username": username,
                "is_friend": are_friends(current_user, username),
                "request_sent": current_user in friend_requests_db.get(username, set()),
                "request_received": username in friend_requests_db.get(current_user, set())
            })
    return {"results": results[:10]}


# ─── WEBSOCKET ────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    token = await websocket.receive_text()

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            await websocket.close()
            return
    except JWTError:
        await websocket.close()
        return

    clients[username] = websocket

    # Notify online friends that this user came online
    for friend in friends_db.get(username, set()):
        await notify_user(friend, {
            "type": "friend_online",
            "username": username,
            "message": f"🟢 {username} is online"
        })

    # Send this user their online friends list
    online_friends = get_online_friends(username)
    await websocket.send_text(json.dumps({
        "type": "online_friends",
        "friends": online_friends
    }))

    # Send pending friend requests
    pending = get_pending_requests(username)
    if pending:
        await websocket.send_text(json.dumps({
            "type": "pending_requests",
            "requests": pending
        }))

    try:
        while True:
            data = await websocket.receive_text()

            try:
                msg_data = json.loads(data)
                msg_type = msg_data.get("type")

                if msg_type == "chat":
                    to_user = msg_data.get("to")
                    message = msg_data.get("message", "")

                    if not are_friends(username, to_user):
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": f"❌ You are not friends with {to_user}"
                        }))
                        continue

                    if to_user not in clients:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": f"❌ {to_user} is not online"
                        }))
                        continue

                    # Send to recipient
                    await clients[to_user].send_text(json.dumps({
                        "type": "chat",
                        "from": username,
                        "message": message
                    }))

                    # Echo back to sender
                    await websocket.send_text(json.dumps({
                        "type": "chat_sent",
                        "to": to_user,
                        "message": message
                    }))

            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        del clients[username]

        # Notify online friends that this user went offline
        for friend in friends_db.get(username, set()):
            await notify_user(friend, {
                "type": "friend_offline",
                "username": username,
                "message": f"🔴 {username} went offline"
            })

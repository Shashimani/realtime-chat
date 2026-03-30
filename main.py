from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, File, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import json, os, cloudinary, cloudinary.uploader
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

app = FastAPI()

SECRET_KEY                  = os.getenv("SECRET_KEY", "change-this-secret")
ALGORITHM                   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30  # 30 days

cloudinary.config(
    cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key    = os.getenv("CLOUDINARY_API_KEY"),
    api_secret = os.getenv("CLOUDINARY_API_SECRET"),
    secure     = True
)

DATABASE_URL = os.getenv("DATABASE_URL")
connection_pool = pool.ThreadedConnectionPool(minconn=1, maxconn=10, dsn=DATABASE_URL)

def get_db():
    conn = connection_pool.getconn()
    conn.cursor_factory = RealDictCursor
    return conn

def release_db(conn):
    connection_pool.putconn(conn)

def init_db():
    conn = get_db(); c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        username        TEXT PRIMARY KEY,
        email           TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        avatar_url      TEXT DEFAULT NULL,
        bio             TEXT DEFAULT '',
        status          TEXT DEFAULT 'Hey there! I am using Chatterly.',
        created_at      TIMESTAMPTZ DEFAULT NOW()
    )""")
    # Add columns if upgrading
    for col, definition in [
        ("bio", "TEXT DEFAULT ''"),
        ("status", "TEXT DEFAULT 'Hey there! I am using Chatterly.'")
    ]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
        except: conn.rollback()

    c.execute("""CREATE TABLE IF NOT EXISTS friends (
        user1 TEXT NOT NULL, user2 TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (user1, user2))""")
    c.execute("""CREATE TABLE IF NOT EXISTS friend_requests (
        from_user TEXT NOT NULL, to_user TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (from_user, to_user))""")
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
        id         SERIAL PRIMARY KEY,
        from_user  TEXT NOT NULL,
        to_user    TEXT NOT NULL,
        message    TEXT NOT NULL,
        msg_type   TEXT DEFAULT 'text',
        media_url  TEXT DEFAULT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
    )""")
    for col, definition in [
        ("msg_type", "TEXT DEFAULT 'text'"),
        ("media_url", "TEXT DEFAULT NULL")
    ]:
        try:
            c.execute(f"ALTER TABLE messages ADD COLUMN {col} {definition}")
        except: conn.rollback()

    conn.commit(); release_db(conn)

init_db()

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
clients       = {}

def hash_password(p):     return pwd_context.hash(p)
def verify_password(p,h): return pwd_context.verify(p, h)

def create_access_token(data):
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username: raise HTTPException(401, "Invalid token")
        return username
    except JWTError:
        raise HTTPException(401, "Invalid token")

async def notify_user(username, message):
    if username in clients:
        try: await clients[username].send_text(json.dumps(message))
        except: pass

# ── DB HELPERS ────────────────────────────────────────────
def db_get_user(username):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT * FROM users WHERE username=%s",(username,))
    row=c.fetchone();release_db(conn)
    return dict(row) if row else None

def db_get_user_by_email(email):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT * FROM users WHERE email=%s",(email,))
    row=c.fetchone();release_db(conn)
    return dict(row) if row else None

def db_create_user(username,email,hashed_password):
    conn=get_db();c=conn.cursor()
    c.execute("INSERT INTO users (username,email,hashed_password) VALUES (%s,%s,%s)",(username,email,hashed_password))
    conn.commit();release_db(conn)

def db_update_profile(username, avatar_url=None, bio=None, status=None):
    conn=get_db();c=conn.cursor()
    updates=[]; params=[]
    if avatar_url is not None: updates.append("avatar_url=%s"); params.append(avatar_url)
    if bio is not None: updates.append("bio=%s"); params.append(bio)
    if status is not None: updates.append("status=%s"); params.append(status)
    if updates:
        params.append(username)
        c.execute(f"UPDATE users SET {','.join(updates)} WHERE username=%s", params)
        conn.commit()
    release_db(conn)

def db_are_friends(u1,u2):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT 1 FROM friends WHERE (user1=%s AND user2=%s) OR (user1=%s AND user2=%s)",(u1,u2,u2,u1))
    row=c.fetchone();release_db(conn)
    return row is not None

def db_get_friends(username):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT CASE WHEN user1=%s THEN user2 ELSE user1 END AS friend FROM friends WHERE user1=%s OR user2=%s",(username,username,username))
    rows=c.fetchall();release_db(conn)
    return [r["friend"] for r in rows]

def db_add_friendship(u1,u2):
    conn=get_db();c=conn.cursor()
    c.execute("INSERT INTO friends (user1,user2) VALUES (%s,%s) ON CONFLICT DO NOTHING",(u1,u2))
    conn.commit();release_db(conn)

def db_request_exists(f,t):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT 1 FROM friend_requests WHERE from_user=%s AND to_user=%s",(f,t))
    row=c.fetchone();release_db(conn);return row is not None

def db_add_request(f,t):
    conn=get_db();c=conn.cursor()
    c.execute("INSERT INTO friend_requests (from_user,to_user) VALUES (%s,%s) ON CONFLICT DO NOTHING",(f,t))
    conn.commit();release_db(conn)

def db_delete_request(f,t):
    conn=get_db();c=conn.cursor()
    c.execute("DELETE FROM friend_requests WHERE from_user=%s AND to_user=%s",(f,t))
    conn.commit();release_db(conn)

def db_get_incoming(u):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT from_user FROM friend_requests WHERE to_user=%s",(u,))
    rows=c.fetchall();release_db(conn);return [r["from_user"] for r in rows]

def db_get_outgoing(u):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT to_user FROM friend_requests WHERE from_user=%s",(u,))
    rows=c.fetchall();release_db(conn);return [r["to_user"] for r in rows]

def db_save_message(from_user,to_user,message,msg_type='text',media_url=None):
    conn=get_db();c=conn.cursor()
    c.execute("INSERT INTO messages (from_user,to_user,message,msg_type,media_url) VALUES (%s,%s,%s,%s,%s) RETURNING id,created_at",
              (from_user,to_user,message,msg_type,media_url))
    row=c.fetchone();conn.commit();release_db(conn)
    return dict(row)

def db_get_messages(u1,u2):
    conn=get_db();c=conn.cursor()
    c.execute("""SELECT id,from_user,to_user,message,msg_type,media_url,created_at FROM messages
        WHERE (from_user=%s AND to_user=%s) OR (from_user=%s AND to_user=%s)
        ORDER BY created_at ASC""",(u1,u2,u2,u1))
    rows=c.fetchall();release_db(conn)
    result=[]
    for r in rows:
        d=dict(r)
        if hasattr(d["created_at"],"isoformat"): d["created_at"]=d["created_at"].isoformat()
        result.append(d)
    return result

def db_search_users(query,current_user):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT username,avatar_url,bio,status FROM users WHERE username ILIKE %s AND username!=%s LIMIT 10",(f"%{query}%",current_user))
    rows=c.fetchall();release_db(conn);return [dict(r) for r in rows]

# ── MODELS ────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str; email: EmailStr; password: str

class Token(BaseModel):
    access_token: str; token_type: str

class FriendReq(BaseModel):
    to_username: str

class FriendAction(BaseModel):
    from_username: str; action: str

class UpdateProfile(BaseModel):
    bio: Optional[str] = None
    status: Optional[str] = None

# ── ROUTES ────────────────────────────────────────────────
@app.get("/")
def get():
    with open("index.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.post("/register")
def register(req: RegisterRequest):
    if db_get_user(req.username): raise HTTPException(400,"Username already taken")
    if len(req.username)<3: raise HTTPException(400,"Username must be at least 3 characters")
    if db_get_user_by_email(req.email): raise HTTPException(400,"Email already registered")
    if len(req.password)<4: raise HTTPException(400,"Password must be at least 4 characters")
    db_create_user(req.username,req.email,hash_password(req.password))
    return {"message":"Registered successfully"}

@app.post("/login",response_model=Token)
def login(form_data: OAuth2PasswordRequestForm=Depends()):
    user=db_get_user(form_data.username) or db_get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password,user["hashed_password"]):
        raise HTTPException(401,"Invalid username/email or password")
    return {"access_token":create_access_token({"sub":user["username"]}),"token_type":"bearer"}

@app.get("/me")
def me(current_user: str=Depends(get_current_user)):
    user=db_get_user(current_user)
    return {"username":user["username"],"email":user["email"],
            "avatar_url":user["avatar_url"],"bio":user.get("bio",""),
            "status":user.get("status","Hey there! I am using Chatterly.")}

@app.post("/update-profile")
async def update_profile(req: UpdateProfile, current_user: str=Depends(get_current_user)):
    db_update_profile(current_user, bio=req.bio, status=req.status)
    # Notify friends of status update
    if req.status is not None:
        for friend in db_get_friends(current_user):
            await notify_user(friend,{"type":"status_update","username":current_user,"status":req.status})
    return {"message":"Profile updated"}

@app.post("/upload-avatar")
async def upload_avatar(file: UploadFile=File(...), current_user: str=Depends(get_current_user)):
    if not file.content_type.startswith("image/"): raise HTTPException(400,"File must be an image")
    contents=await file.read()
    result=cloudinary.uploader.upload(contents,
        public_id=f"chatterly/avatars/{current_user}",
        overwrite=True,crop="fill",width=400,height=400,
        gravity="face",fetch_format="auto",quality="auto",invalidate=True)
    avatar_url=result["secure_url"]
    db_update_profile(current_user, avatar_url=avatar_url)
    versioned=f"{avatar_url}?v={int(datetime.utcnow().timestamp())}"
    for friend in db_get_friends(current_user):
        await notify_user(friend,{"type":"avatar_update","username":current_user,"avatar_url":versioned})
    return {"avatar_url":versioned}

@app.post("/upload-media")
async def upload_media(file: UploadFile=File(...), current_user: str=Depends(get_current_user)):
    """Upload image or video for chat messages"""
    is_video=file.content_type.startswith("video/")
    is_image=file.content_type.startswith("image/")
    if not is_image and not is_video:
        raise HTTPException(400,"File must be an image or video")
    contents=await file.read()
    # Max 50MB
    if len(contents) > 50*1024*1024:
        raise HTTPException(400,"File too large (max 50MB)")

    resource_type="video" if is_video else "image"
    result=cloudinary.uploader.upload(contents,
        folder=f"chatterly/media",
        resource_type=resource_type,
        fetch_format="auto",quality="auto")
    return {
        "url": result["secure_url"],
        "type": "video" if is_video else "image",
        "thumbnail": result.get("secure_url","").replace("/upload/","/upload/w_400,h_300,c_fill/") if is_video else None
    }

@app.get("/messages/{friend}")
def get_messages(friend: str, current_user: str=Depends(get_current_user)):
    if not db_are_friends(current_user,friend): raise HTTPException(403,"Not friends")
    return {"messages":db_get_messages(current_user,friend)}

@app.post("/friend/request")
async def send_friend_request(req: FriendReq, current_user: str=Depends(get_current_user)):
    to=req.to_username
    if not db_get_user(to): raise HTTPException(404,"User not found")
    if to==current_user: raise HTTPException(400,"Cannot add yourself")
    if db_are_friends(current_user,to): raise HTTPException(400,"Already friends")
    if db_request_exists(current_user,to): raise HTTPException(400,"Request already sent")
    if db_request_exists(to,current_user):
        db_delete_request(to,current_user);db_add_friendship(current_user,to)
        await notify_user(to,{"type":"friend_accepted","from":current_user,"message":f"🤝 {current_user} is now your friend!"})
        await notify_user(current_user,{"type":"friend_accepted","from":to,"message":f"🤝 {to} is now your friend!"})
        return {"message":"Accepted automatically"}
    db_add_request(current_user,to)
    await notify_user(to,{"type":"friend_request","from":current_user,"message":f"👋 {current_user} sent you a friend request"})
    return {"message":f"Friend request sent to {to}"}

@app.post("/friend/respond")
async def respond_friend_request(action: FriendAction, current_user: str=Depends(get_current_user)):
    fu=action.from_username
    if not db_request_exists(fu,current_user): raise HTTPException(400,"No request from this user")
    db_delete_request(fu,current_user)
    if action.action=="accept":
        db_add_friendship(current_user,fu)
        await notify_user(fu,{"type":"friend_accepted","from":current_user,"message":f"🤝 {current_user} accepted your request!"})
        await notify_user(current_user,{"type":"friend_accepted","from":fu,"message":f"🤝 Now friends with {fu}!"})
        return {"message":f"Now friends with {fu}"}
    await notify_user(fu,{"type":"friend_rejected","from":current_user,"message":f"❌ {current_user} declined your request."})
    return {"message":"Declined"}

@app.get("/friends")
def get_friends(current_user: str=Depends(get_current_user)):
    friends=db_get_friends(current_user)
    online=[u for u in friends if u in clients]
    friends_info=[]
    for f in friends:
        u=db_get_user(f)
        if u: friends_info.append({"username":f,"avatar_url":u["avatar_url"],"status":u.get("status",""),"bio":u.get("bio","")})
    return {"friends":friends,"friends_info":friends_info,"online_friends":online,
            "pending_incoming":db_get_incoming(current_user),"pending_outgoing":db_get_outgoing(current_user)}

@app.get("/users/search")
def search_users(q: str, current_user: str=Depends(get_current_user)):
    users=db_search_users(q,current_user)
    results=[]
    for u in users:
        results.append({"username":u["username"],"avatar_url":u["avatar_url"],
            "bio":u.get("bio",""),"status":u.get("status",""),
            "is_friend":db_are_friends(current_user,u["username"]),
            "request_sent":db_request_exists(current_user,u["username"]),
            "request_received":db_request_exists(u["username"],current_user)})
    return {"results":results}

# ── WEBSOCKET ─────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    token=await websocket.receive_text()
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username=payload.get("sub")
        if not username: await websocket.close(); return
    except JWTError:
        await websocket.close(); return

    clients[username]=websocket
    friends=db_get_friends(username)
    for friend in friends:
        await notify_user(friend,{"type":"friend_online","username":username})
    online_friends=[u for u in friends if u in clients]
    await websocket.send_text(json.dumps({"type":"online_friends","friends":online_friends}))
    pending=db_get_incoming(username)
    if pending:
        await websocket.send_text(json.dumps({"type":"pending_requests","requests":pending}))

    try:
        while True:
            data=await websocket.receive_text()
            try:
                msg_data=json.loads(data)
                msg_type=msg_data.get("type")

                if msg_type=="chat":
                    to_user=msg_data.get("to")
                    message=msg_data.get("message","").strip()
                    mtype=msg_data.get("msg_type","text")
                    media_url=msg_data.get("media_url",None)
                    if not message and not media_url: continue
                    if not db_are_friends(username,to_user):
                        await websocket.send_text(json.dumps({"type":"error","message":"❌ Not friends"})); continue
                    saved=db_save_message(username,to_user,message or "",mtype,media_url)
                    payload_out={
                        "type":"chat","from":username,
                        "message":message,"msg_type":mtype,
                        "media_url":media_url,
                        "created_at":saved["created_at"].isoformat() if hasattr(saved["created_at"],"isoformat") else str(saved["created_at"])
                    }
                    if to_user in clients:
                        await clients[to_user].send_text(json.dumps(payload_out))
                    await websocket.send_text(json.dumps({**payload_out,"type":"chat_sent","to":to_user}))

                elif msg_type in ("call_offer","call_answer","call_ice","call_reject","call_end","call_busy"):
                    to_user=msg_data.get("to")
                    if to_user and to_user in clients:
                        msg_data["from"]=username
                        await clients[to_user].send_text(json.dumps(msg_data))

            except json.JSONDecodeError: pass
    except WebSocketDisconnect:
        if username in clients: del clients[username]
        for friend in db_get_friends(username):
            await notify_user(friend,{"type":"friend_offline","username":username})

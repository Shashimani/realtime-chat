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

load_dotenv()

app = FastAPI()

SECRET_KEY                  = os.getenv("SECRET_KEY", "change-this-secret")
ALGORITHM                   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30  # 30 days so refresh keeps user logged in

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
        username TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL, avatar_url TEXT DEFAULT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW())""")
    c.execute("""CREATE TABLE IF NOT EXISTS friends (
        user1 TEXT NOT NULL, user2 TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (user1, user2))""")
    c.execute("""CREATE TABLE IF NOT EXISTS friend_requests (
        from_user TEXT NOT NULL, to_user TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (from_user, to_user))""")
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY, from_user TEXT NOT NULL, to_user TEXT NOT NULL,
        message TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW())""")
    conn.commit(); release_db(conn)

init_db()

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
clients       = {}  # { username: websocket }

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

def db_set_avatar(username,avatar_url):
    conn=get_db();c=conn.cursor()
    c.execute("UPDATE users SET avatar_url=%s WHERE username=%s",(avatar_url,username))
    conn.commit();release_db(conn)

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

def db_request_exists(from_user,to_user):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT 1 FROM friend_requests WHERE from_user=%s AND to_user=%s",(from_user,to_user))
    row=c.fetchone();release_db(conn)
    return row is not None

def db_add_request(from_user,to_user):
    conn=get_db();c=conn.cursor()
    c.execute("INSERT INTO friend_requests (from_user,to_user) VALUES (%s,%s) ON CONFLICT DO NOTHING",(from_user,to_user))
    conn.commit();release_db(conn)

def db_delete_request(from_user,to_user):
    conn=get_db();c=conn.cursor()
    c.execute("DELETE FROM friend_requests WHERE from_user=%s AND to_user=%s",(from_user,to_user))
    conn.commit();release_db(conn)

def db_get_incoming_requests(username):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT from_user FROM friend_requests WHERE to_user=%s",(username,))
    rows=c.fetchall();release_db(conn)
    return [r["from_user"] for r in rows]

def db_get_outgoing_requests(username):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT to_user FROM friend_requests WHERE from_user=%s",(username,))
    rows=c.fetchall();release_db(conn)
    return [r["to_user"] for r in rows]

def db_save_message(from_user,to_user,message):
    conn=get_db();c=conn.cursor()
    c.execute("INSERT INTO messages (from_user,to_user,message) VALUES (%s,%s,%s)",(from_user,to_user,message))
    conn.commit();release_db(conn)

def db_get_messages(u1,u2):
    conn=get_db();c=conn.cursor()
    c.execute("""SELECT from_user,to_user,message,created_at FROM messages
        WHERE (from_user=%s AND to_user=%s) OR (from_user=%s AND to_user=%s)
        ORDER BY created_at ASC""",(u1,u2,u2,u1))
    rows=c.fetchall();release_db(conn)
    return [dict(r) for r in rows]

def db_search_users(query,current_user):
    conn=get_db();c=conn.cursor()
    c.execute("SELECT username,avatar_url FROM users WHERE username ILIKE %s AND username!=%s LIMIT 10",(f"%{query}%",current_user))
    rows=c.fetchall();release_db(conn)
    return [dict(r) for r in rows]

# ── MODELS ────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str; email: EmailStr; password: str

class Token(BaseModel):
    access_token: str; token_type: str

class FriendReq(BaseModel):
    to_username: str

class FriendAction(BaseModel):
    from_username: str; action: str

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
    return {"username":user["username"],"email":user["email"],"avatar_url":user["avatar_url"]}

@app.post("/upload-avatar")
async def upload_avatar(file: UploadFile=File(...),current_user: str=Depends(get_current_user)):
    if not file.content_type.startswith("image/"): raise HTTPException(400,"File must be an image")
    contents=await file.read()
    result=cloudinary.uploader.upload(contents,
        public_id=f"chatterly/avatars/{current_user}",
        overwrite=True,crop="fill",width=200,height=200,
        gravity="face",fetch_format="auto",quality="auto",invalidate=True)
    avatar_url=result["secure_url"]
    db_set_avatar(current_user,avatar_url)
    # Send with version timestamp to bust CDN cache
    versioned_url=f"{avatar_url}?v={int(datetime.utcnow().timestamp())}"
    for friend in db_get_friends(current_user):
        await notify_user(friend,{"type":"avatar_update","username":current_user,"avatar_url":versioned_url})
    return {"avatar_url":versioned_url}

@app.get("/messages/{friend}")
def get_messages(friend: str,current_user: str=Depends(get_current_user)):
    if not db_are_friends(current_user,friend): raise HTTPException(403,"Not friends")
    msgs=db_get_messages(current_user,friend)
    for m in msgs:
        if hasattr(m["created_at"],"isoformat"): m["created_at"]=m["created_at"].isoformat()
    return {"messages":msgs}

@app.post("/friend/request")
async def send_friend_request(req: FriendReq,current_user: str=Depends(get_current_user)):
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
async def respond_friend_request(action: FriendAction,current_user: str=Depends(get_current_user)):
    from_user=action.from_username
    if not db_request_exists(from_user,current_user): raise HTTPException(400,"No request from this user")
    db_delete_request(from_user,current_user)
    if action.action=="accept":
        db_add_friendship(current_user,from_user)
        await notify_user(from_user,{"type":"friend_accepted","from":current_user,"message":f"🤝 {current_user} accepted your request!"})
        await notify_user(current_user,{"type":"friend_accepted","from":from_user,"message":f"🤝 Now friends with {from_user}!"})
        return {"message":f"Now friends with {from_user}"}
    elif action.action=="reject":
        await notify_user(from_user,{"type":"friend_rejected","from":current_user,"message":f"❌ {current_user} declined your request."})
        return {"message":"Declined"}
    raise HTTPException(400,"Invalid action")

@app.get("/friends")
def get_friends(current_user: str=Depends(get_current_user)):
    friends=db_get_friends(current_user)
    online=[u for u in friends if u in clients]
    friends_info=[]
    for f in friends:
        u=db_get_user(f)
        friends_info.append({"username":f,"avatar_url":u["avatar_url"] if u else None})
    return {"friends":friends,"friends_info":friends_info,"online_friends":online,
            "pending_incoming":db_get_incoming_requests(current_user),
            "pending_outgoing":db_get_outgoing_requests(current_user)}

@app.get("/users/search")
def search_users(q: str,current_user: str=Depends(get_current_user)):
    users=db_search_users(q,current_user)
    results=[]
    for u in users:
        results.append({"username":u["username"],"avatar_url":u["avatar_url"],
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
    pending=db_get_incoming_requests(username)
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
                    if not message: continue
                    if not db_are_friends(username,to_user):
                        await websocket.send_text(json.dumps({"type":"error","message":"❌ Not friends"})); continue
                    db_save_message(username,to_user,message)
                    now=datetime.utcnow().strftime("%H:%M")
                    if to_user in clients:
                        await clients[to_user].send_text(json.dumps({"type":"chat","from":username,"message":message,"time":now}))
                    await websocket.send_text(json.dumps({"type":"chat_sent","to":to_user,"message":message,"time":now}))

                # ── WebRTC Signaling - just relay between peers ──
                elif msg_type in ("call_offer","call_answer","call_ice","call_reject","call_end","call_busy"):
                    to_user=msg_data.get("to")
                    if to_user and to_user in clients:
                        msg_data["from"]=username
                        await clients[to_user].send_text(json.dumps(msg_data))

            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        if username in clients: del clients[username]
        for friend in db_get_friends(username):
            await notify_user(friend,{"type":"friend_offline","username":username})

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

app = FastAPI()

clients = {}  # username -> websocket


@app.get("/")
def get():
    with open("index.html") as f:
        return HTMLResponse(f.read())


async def broadcast_users():
    user_list = "USERS:" + ",".join(clients.keys())
    for conn in clients.values():
        await conn.send_text(user_list)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    username = await websocket.receive_text()
    clients[username] = websocket

    # Notify join
    for conn in clients.values():
        await conn.send_text(f"🟢 {username} joined")

    await broadcast_users()

    try:
        while True:
            data = await websocket.receive_text()

            # FORMAT: to|message
            if "|" in data:
                to_user, message = data.split("|", 1)

                if to_user in clients:
                    await clients[to_user].send_text(f"💬 {username} (private): {message}")
                    await websocket.send_text(f"📤 You to {to_user}: {message}")
                else:
                    await websocket.send_text("❌ User not online")
            else:
                # Broadcast message
                for conn in clients.values():
                    await conn.send_text(f"{username}: {data}")

    except WebSocketDisconnect:
        del clients[username]

        for conn in clients.values():
            await conn.send_text(f"🔴 {username} left")

        await broadcast_users()
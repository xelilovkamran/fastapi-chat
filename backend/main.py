from fastapi import FastAPI, WebSocket, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import List, Optional
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import json
from passlib.context import CryptContext
import models
import schemas
from database import engine, get_db
from jose import JWTError, jwt
from dotenv import load_dotenv
import os

load_dotenv()

# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))


# OAuth2 scheme
security = HTTPBearer()


# Dictionary to store connected WebSocket clients
connected_users = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire.timestamp()})
    encoded_jwt = jwt.encode(
        to_encode, SECRET_KEY, algorithm=ALGORITHM
    )
    return encoded_jwt


def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM]
        )
        return payload
    except JWTError:
        return None


async def get_current_user(
    auth_credentials: HTTPBearer = Depends(security),
    db: Session = Depends(get_db)
) -> schemas.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        token = auth_credentials.credentials
        payload = verify_token(token)

        if payload is None:
            raise credentials_exception

        user = db.query(models.User).filter(
            models.User.email == payload.get("sub")).first()
        if user is None:
            raise credentials_exception

        return user
    except Exception:
        raise credentials_exception


@app.get("/me", response_model=schemas.User)
def read_users_me(
    current_user: schemas.User = Depends(get_current_user)
) -> schemas.User:
    return current_user


@app.get("/users/list", response_model=List[schemas.User])
async def get_users(current_user: schemas.User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(models.User).filter(
        models.User.id != current_user.id).all()
    return users


@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(
        models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post("/token")
async def login(login_data: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(
        models.User.email == login_data.email).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer", "user_id": user.id}


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(
    user_id: str,
    websocket: WebSocket,
    db: Session = Depends(get_db)
):
    await websocket.accept()
    connected_users[user_id] = websocket

    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)

            # Save message to database
            db_message = models.Message(
                content=message_data["content"],
                sender_id=int(user_id),
                receiver_id=message_data.get("receiver_id")
            )
            db.add(db_message)
            db.commit()

            # Send the received data to the specific receiver
            receiver_ws = connected_users.get(
                str(message_data.get("receiver_id")))
            if receiver_ws:
                await receiver_ws.send_text(json.dumps({
                    "content": message_data["content"],
                    "sender_id": int(user_id)
                }))
    except Exception as e:
        print(f"Error: {e}")
        del connected_users[user_id]
        await websocket.close()
    finally:
        if user_id in connected_users:
            del connected_users[user_id]


@app.get("/messages/{user_id}", response_model=List[schemas.Message])
async def get_user_messages(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    messages = db.query(models.Message).filter(
        ((models.Message.sender_id == current_user.id) &
         (models.Message.receiver_id == user_id)) |
        ((models.Message.sender_id == user_id) &
         (models.Message.receiver_id == current_user.id))
    ).all()
    return messages

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

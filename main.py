import os
from datetime import datetime, timedelta, timezone, date as date_cls
import hashlib
import uuid
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Session as SessionSchema, Shift as ShiftSchema, Notification as NotificationSchema

app = FastAPI(title="Bakery Workforce Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Helpers --------------------

def to_object_id(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def doc_to_dict(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    return doc


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or uuid.uuid4().hex
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt, hashed = password_hash.split("$")
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    except Exception:
        return False


# -------------------- Startup seeding --------------------
@app.on_event("startup")
def ensure_admin_user():
    try:
        existing_admin = db["user"].find_one({"is_admin": True})
        if not existing_admin:
            username = os.getenv("ADMIN_USERNAME", "admin")
            password = os.getenv("ADMIN_PASSWORD", "admin123")
            user_doc = UserSchema(
                username=username,
                full_name=os.getenv("ADMIN_FULL_NAME", "Администратор"),
                role="admin",
                is_admin=True,
                password_hash=hash_password(password),
                active=True
            )
            db["user"].insert_one(user_doc.model_dump())
            # also drop any stale sessions for safety
            db["session"].delete_many({})
            print("[startup] Default admin created:", username)
        else:
            print("[startup] Admin user exists")
    except Exception as e:
        print("[startup] Admin seed error:", e)


# -------------------- Auth dependencies --------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    full_name: str
    role: str = Field(..., description="baker|cashier|cleaner|admin")
    is_admin: bool = False
    password: str
    active: bool = True


class UpdateUserRequest(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_admin: Optional[bool] = None
    active: Optional[bool] = None
    password: Optional[str] = None


def get_session_by_token(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    session = db["session"].find_one({"token": token})
    if session and session.get("expires_at") and session["expires_at"] < datetime.now(timezone.utc):
        # expired -> delete
        db["session"].delete_one({"_id": session["_id"]})
        return None
    return session


def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")
    parts = authorization.split()
    token = parts[-1]
    session = get_session_by_token(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    user = db["user"].find_one({"_id": session["user_id"]})
    if not user or not user.get("active", True):
        raise HTTPException(status_code=403, detail="User inactive or not found")
    user_dict = doc_to_dict(user)
    user_dict.pop("password_hash", None)
    user_dict["token"] = token
    return user_dict


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# -------------------- Basic routes --------------------
@app.get("/")
def read_root():
    return {"message": "Bakery Workforce API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
        else:
            response["database"] = "❌ Not Available"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# -------------------- Auth --------------------
@app.post("/api/auth/login")
def login(payload: LoginRequest):
    user = db["user"].find_one({"username": payload.username})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("active", True):
        raise HTTPException(status_code=403, detail="User is inactive")
    token = uuid.uuid4().hex
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    session_doc = SessionSchema(user_id=str(user["_id"]), token=token, expires_at=expires)
    db["session"].insert_one({
        "user_id": user["_id"],
        "token": token,
        "expires_at": expires
    })
    user_out = doc_to_dict(user)
    user_out.pop("password_hash", None)
    return {"token": token, "user": user_out}


@app.get("/api/auth/me")
def me(user=Depends(get_current_user)):
    return user


@app.post("/api/auth/logout")
def logout(user=Depends(get_current_user)):
    token = user.get("token")
    if token:
        db["session"].delete_many({"token": token})
    return {"ok": True}


# -------------------- Users (Admin) --------------------
@app.get("/api/users")
def list_users(_: Dict[str, Any] = Depends(require_admin)):
    users = []
    for u in db["user"].find({}).sort("full_name"):
        u = doc_to_dict(u)
        u.pop("password_hash", None)
        users.append(u)
    return users


@app.post("/api/users")
def create_user(payload: CreateUserRequest, _: Dict[str, Any] = Depends(require_admin)):
    if db["user"].find_one({"username": payload.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    password_hash = hash_password(payload.password)
    user_doc = UserSchema(
        username=payload.username,
        full_name=payload.full_name,
        role=payload.role,
        is_admin=payload.is_admin,
        password_hash=password_hash,
        active=payload.active
    )
    user_id = db["user"].insert_one(user_doc.model_dump()).inserted_id
    user = db["user"].find_one({"_id": user_id})
    out = doc_to_dict(user)
    out.pop("password_hash", None)
    return out


@app.put("/api/users/{user_id}")
def update_user(user_id: str, payload: UpdateUserRequest, _: Dict[str, Any] = Depends(require_admin)):
    updates: Dict[str, Any] = {}
    if payload.full_name is not None:
        updates["full_name"] = payload.full_name
    if payload.role is not None:
        updates["role"] = payload.role
    if payload.is_admin is not None:
        updates["is_admin"] = payload.is_admin
    if payload.active is not None:
        updates["active"] = payload.active
    if payload.password is not None:
        updates["password_hash"] = hash_password(payload.password)
    if not updates:
        return {"ok": True}
    res = db["user"].update_one({"_id": to_object_id(user_id)}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    user = db["user"].find_one({"_id": to_object_id(user_id)})
    out = doc_to_dict(user)
    out.pop("password_hash", None)
    return out


@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, _: Dict[str, Any] = Depends(require_admin)):
    db["user"].delete_one({"_id": to_object_id(user_id)})
    # Clean up sessions
    db["session"].delete_many({"user_id": to_object_id(user_id)})
    return {"ok": True}


# -------------------- Shifts --------------------
class ShiftCreateRequest(BaseModel):
    user_id: str
    date: str
    start_time: str
    end_time: str
    note: Optional[str] = None


@app.get("/api/shifts")
def get_shifts(start: Optional[str] = None, end: Optional[str] = None, user=Depends(get_current_user)):
    filt: Dict[str, Any] = {}
    if start or end:
        dr: Dict[str, Any] = {}
        if start:
            dr["$gte"] = start
        if end:
            dr["$lte"] = end
        filt["date"] = dr
    # Query as strings in ISO format to keep it simple
    shifts = []
    for s in db["shift"].find(filt).sort([("date", 1), ("start_time", 1)]):
        s = doc_to_dict(s)
        # enrich with user name
        u = db["user"].find_one({"_id": to_object_id(s["user_id"])}) if ObjectId.is_valid(s.get("user_id", "")) else None
        s["user_name"] = u.get("full_name") if u else "Unknown"
        shifts.append(s)
    return shifts


@app.post("/api/shifts")
def create_shift(payload: ShiftCreateRequest, _: Dict[str, Any] = Depends(require_admin)):
    # Store as strings (ISO) for date and HH:MM for times for simplicity
    doc = {
        "user_id": payload.user_id,
        "date": payload.date,
        "start_time": payload.start_time,
        "end_time": payload.end_time,
        "note": payload.note,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    inserted = db["shift"].insert_one(doc)
    created = db["shift"].find_one({"_id": inserted.inserted_id})
    return doc_to_dict(created)


@app.put("/api/shifts/{shift_id}")
def update_shift(shift_id: str, payload: ShiftCreateRequest, _: Dict[str, Any] = Depends(require_admin)):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    updates["updated_at"] = datetime.now(timezone.utc)
    res = db["shift"].update_one({"_id": to_object_id(shift_id)}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Shift not found")
    s = db["shift"].find_one({"_id": to_object_id(shift_id)})
    return doc_to_dict(s)


@app.delete("/api/shifts/{shift_id}")
def delete_shift(shift_id: str, _: Dict[str, Any] = Depends(require_admin)):
    db["shift"].delete_one({"_id": to_object_id(shift_id)})
    return {"ok": True}


# -------------------- Notifications --------------------
class NotificationCreateRequest(BaseModel):
    title: str
    message: str
    level: str = "info"
    audience: str = "all"  # all | role:<role> | user:<id>


@app.get("/api/notifications")
def list_notifications(user=Depends(get_current_user)):
    role = user.get("role")
    uid = user.get("id")
    filt = {"$or": [
        {"audience": "all"},
        {"audience": f"role:{role}"},
        {"audience": f"user:{uid}"}
    ]}
    notes = [doc_to_dict(n) for n in db["notification"].find(filt).sort("_id", -1).limit(20)]
    return notes


@app.post("/api/notifications")
def create_notification(payload: NotificationCreateRequest, _: Dict[str, Any] = Depends(require_admin)):
    n = NotificationSchema(**payload.model_dump())
    inserted = db["notification"].insert_one(n.model_dump())
    doc = db["notification"].find_one({"_id": inserted.inserted_id})
    return doc_to_dict(doc)


@app.delete("/api/notifications/{note_id}")
def delete_notification(note_id: str, _: Dict[str, Any] = Depends(require_admin)):
    db["notification"].delete_one({"_id": to_object_id(note_id)})
    return {"ok": True}


# -------------------- Summary --------------------
@app.get("/api/summary")
def summary(user=Depends(get_current_user)):
    # Next 14 days shifts for this user
    today = datetime.now(timezone.utc).date()
    end_day = today + timedelta(days=14)
    start_str = today.isoformat()
    end_str = end_day.isoformat()

    # user's shifts
    shifts = [
        doc_to_dict(s) for s in db["shift"].find({
            "user_id": user["id"],
            "date": {"$gte": start_str, "$lte": end_str}
        }).sort("date", 1)
    ]

    # hours this week (from Monday)
    monday = today - timedelta(days=today.weekday())
    week_end = monday + timedelta(days=6)
    week_shifts = db["shift"].find({
        "user_id": user["id"],
        "date": {"$gte": monday.isoformat(), "$lte": week_end.isoformat()}
    })

    def hours_between(start_hm: str, end_hm: str) -> float:
        try:
            sh, sm = map(int, start_hm.split(":"))
            eh, em = map(int, end_hm.split(":"))
            mins = (eh * 60 + em) - (sh * 60 + sm)
            return max(mins, 0) / 60.0
        except Exception:
            return 0.0

    total_hours = 0.0
    for s in week_shifts:
        total_hours += hours_between(s.get("start_time", "0:0"), s.get("end_time", "0:0"))

    # notifications
    notes = list_notifications(user)

    return {
        "user": user,
        "upcoming_shifts": shifts,
        "weekly_hours": round(total_hours, 2),
        "notifications": notes
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

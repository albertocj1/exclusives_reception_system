import os
import json
import base64
import secrets
from datetime import datetime, timezone, timedelta
from typing import Literal, Optional
from email.message import EmailMessage

from fastapi import Depends, FastAPI, Header, HTTPException, status, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from supabase import Client, create_client

# Branded confirmation email + inline QR (see email_module.py)
from email_module import send_approval_email

EVENT_CAPACITY = int(os.getenv("EVENT_CAPACITY", "300"))
PACKAGES = {
    "Entrance Fee":           {"price": 2500,  "per": "person", "max_guests": 8},
    "Standing Table (4 pax)": {"price": 8000,  "per": "table",  "max_guests": 4},
    "Couch (6 pax)":          {"price": 15000, "per": "table",  "max_guests": 6},
    "Couch (8 pax)":          {"price": 20000, "per": "table",  "max_guests": 8},
}

_client: Optional[Client] = None
def db() -> Client:
    global _client
    if _client is None:
        _client = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])
    return _client

# --- PYDANTIC SCHEMAS ---
class BookingCreate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=120)
    email: EmailStr
    phone: str = Field(..., min_length=7, max_length=20)
    instagram: Optional[str] = None
    referrer: Optional[str] = None
    package: str
    table_id: Optional[str] = None
    guests: int = Field(..., ge=1, le=8)
    accept_terms: bool

    @field_validator("accept_terms")
    @classmethod
    def _terms(cls, v):
        if not v:
            raise ValueError("Must confirm terms.")
        return v

    @field_validator("package")
    @classmethod
    def _known_package(cls, v):
        if v not in PACKAGES:
            raise ValueError(f"Unknown package: {v}")
        return v

    @model_validator(mode="after")
    def _guests_within_package(self):
        max_guests = PACKAGES[self.package]["max_guests"]
        if self.guests > max_guests:
            raise ValueError(f"{self.package} allows at most {max_guests} guests.")
        if PACKAGES[self.package]["per"] == "table" and not self.table_id:
            raise ValueError("This package requires selecting a table.")
        return self

class Booking(BaseModel):
    id: str
    full_name: str
    email: EmailStr
    phone: str
    package: str
    table_id: Optional[str] = None
    guests: int
    total_amount: int
    status: str
    receipt_url: Optional[str] = None
    ticket_code: Optional[str] = None
    created_at: datetime

class CheckinBody(BaseModel):
    heads_present: int = Field(..., ge=0, le=50)

app = FastAPI()

# Dynamically handle allowed origins from your .env string
origins_str = os.environ.get("ALLOWED_ORIGINS", "*")
if origins_str == "*":
    origins_list = ["*"]
else:
    origins_list = [origin.strip() for origin in origins_str.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins_list,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
#  AUTH DEPENDENCIES
# ---------------------------------------------------------------------------

def require_admin(x_admin_key: str = Header(default="")):
    if not secrets.compare_digest(x_admin_key, os.environ.get("ADMIN_API_KEY", "")):
        raise HTTPException(status_code=401, detail="Invalid admin key.")

# Reception staff authenticate via Supabase Auth (email/password on the frontend).
# The frontend sends the resulting access token as "Authorization: Bearer <jwt>".
# We verify it by asking Supabase to resolve the user for that token — this works
# regardless of whether the project uses the legacy shared secret or the newer
# asymmetric signing keys.
_reception_bearer = HTTPBearer(auto_error=False)

def require_reception(cred: Optional[HTTPAuthorizationCredentials] = Depends(_reception_bearer)):
    if cred is None or not cred.credentials:
        raise HTTPException(status_code=401, detail="Reception login required.")
    token = cred.credentials
    try:
        user_resp = db().auth.get_user(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    user = getattr(user_resp, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session.")
    return user

# ---------------------------------------------------------------------------
#  HELPERS
# ---------------------------------------------------------------------------

def _get_booking(booking_id: str):
    res = db().table("bookings").select("*").eq("id", booking_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="Not found.")
    return res.data[0]

def _confirmed_guest_count() -> int:
    res = db().table("bookings").select("guests").eq("status", "confirmed").execute()
    return sum(row["guests"] for row in (res.data or []))

def _table_capacity(package_name: Optional[str]) -> Optional[int]:
    cfg = PACKAGES.get(package_name or "")
    return cfg["max_guests"] if cfg else None

# ---------------------------------------------------------------------------
#  PUBLIC ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/api/availability")
def availability():
    taken = _confirmed_guest_count()
    return {"capacity": EVENT_CAPACITY, "taken": taken, "spots_left": max(0, EVENT_CAPACITY - taken)}

@app.get("/api/tables/availability")
def get_tables():
    all_tables = db().table("tables").select("*").execute().data
    lock_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()

    confirmed = db().table("bookings").select("table_id") \
        .eq("status", "confirmed") \
        .not_.is_("table_id", "null") \
        .execute()

    holds = db().table("bookings").select("table_id") \
        .in_("status", ["pending", "verifying"]) \
        .gte("created_at", lock_cutoff) \
        .not_.is_("table_id", "null") \
        .execute()

    taken_ids = {r["table_id"] for r in (confirmed.data or []) if r.get("table_id")}
    taken_ids |= {r["table_id"] for r in (holds.data or []) if r.get("table_id")}

    for t in all_tables:
        t["is_available"] = t["id"] not in taken_ids
    return {"tables": all_tables}

@app.post("/api/bookings", response_model=Booking)
def create_booking(payload: BookingCreate):
    if payload.table_id:
        lock_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()

        confirmed = db().table("bookings").select("id") \
            .eq("table_id", payload.table_id) \
            .eq("status", "confirmed") \
            .execute()

        held = db().table("bookings").select("id") \
            .eq("table_id", payload.table_id) \
            .in_("status", ["pending", "verifying"]) \
            .gte("created_at", lock_cutoff) \
            .execute()

        if confirmed.data or held.data:
            raise HTTPException(status_code=409, detail="Table just got reserved by someone else.")

    unit = PACKAGES[payload.package]["price"]
    total = unit * payload.guests if PACKAGES[payload.package]["per"] == "person" else unit

    try:
        res = db().table("bookings").insert({
            "full_name": payload.full_name, "email": payload.email, "phone": payload.phone,
            "instagram": payload.instagram, "referrer": payload.referrer,
            "package": payload.package, "table_id": payload.table_id, "guests": payload.guests,
            "unit_price": unit, "total_amount": total, "status": "pending",
        }).execute()
    except Exception as e:
        if "23505" in str(e) or "duplicate key" in str(e).lower():
            raise HTTPException(status_code=409, detail="Table just got reserved by someone else.")
        raise

    return Booking(**res.data[0])

@app.post("/api/bookings/{booking_id}/submit-payment", response_model=Booking)
async def submit_payment(booking_id: str, receipt: UploadFile = File(...)):
    booking = _get_booking(booking_id)
    if booking["status"] != "pending":
        raise HTTPException(status_code=400, detail="Cannot submit payment for this booking.")

    file_bytes = await receipt.read()
    file_ext = receipt.filename.split(".")[-1] if "." in receipt.filename else "jpg"
    file_name = f"{booking_id}_{secrets.token_hex(4)}.{file_ext}"

    try:
        db().storage.from_("receipts").upload(file_name, file_bytes, {"content-type": receipt.content_type})
        receipt_url = db().storage.from_("receipts").get_public_url(file_name)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not upload receipt: {str(e)}")

    res = db().table("bookings").update({
        "status": "verifying", "receipt_url": receipt_url
    }).eq("id", booking_id).execute()
    return Booking(**res.data[0])

# ---------------------------------------------------------------------------
#  ADMIN ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/api/bookings", dependencies=[Depends(require_admin)])
def list_bookings():
    return db().table("bookings").select("*").order("created_at", desc=True).limit(1000).execute().data

@app.post("/api/bookings/{booking_id}/approve", dependencies=[Depends(require_admin)])
def approve_booking(booking_id: str, background_tasks: BackgroundTasks):
    b = _get_booking(booking_id)
    if b["status"] != "verifying":
        raise HTTPException(status_code=400, detail="Not awaiting verification.")

    try:
        res = db().table("bookings").update({
            "status": "confirmed",
            "ticket_code": "EXC-" + secrets.token_hex(3).upper(),
            "confirmed_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", booking_id).execute()
    except Exception as e:
        if "23505" in str(e) or "duplicate key" in str(e).lower():
            raise HTTPException(
                status_code=409,
                detail="That table is already confirmed for another guest. Cancel one before approving.",
            )
        raise

    if res.data:
        booking_data = res.data[0]
        background_tasks.add_task(
            send_approval_email,
            to_email=booking_data["email"],
            guest_name=booking_data["full_name"],
            ticket_code=booking_data["ticket_code"],
            package_name=booking_data["package"],
            guests=booking_data["guests"],
            table_id=booking_data.get("table_id"),
        )
        return Booking(**booking_data)
    raise HTTPException(status_code=502, detail="Failed to issue ticket.")

@app.post("/api/bookings/{booking_id}/cancel", dependencies=[Depends(require_admin)])
def cancel_booking(booking_id: str):
    res = db().table("bookings").update({"status": "cancelled"}).eq("id", booking_id).execute()
    return Booking(**res.data[0])

# ---------------------------------------------------------------------------
#  RECEPTION ENDPOINTS  (Supabase-Auth protected)
# ---------------------------------------------------------------------------

@app.get("/api/reception/lookup/{ticket_code}", dependencies=[Depends(require_reception)])
def reception_lookup(ticket_code: str):
    """Scan/lookup a ticket code -> return guest details + current check-in state."""
    code = (ticket_code or "").strip().upper()
    res = db().table("bookings").select("*").eq("ticket_code", code).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="Ticket not found.")
    b = res.data[0]
    return {
        "id": b["id"],
        "ticket_code": b.get("ticket_code"),
        "full_name": b["full_name"],
        "package": b["package"],
        "table_id": b.get("table_id"),
        "guests": b["guests"],
        "status": b["status"],
        "checked_in": b.get("checked_in", False),
        "checked_in_at": b.get("checked_in_at"),
        "heads_present": b.get("heads_present", 0),
    }

@app.post("/api/reception/checkin/{booking_id}", dependencies=[Depends(require_reception)])
def reception_checkin(booking_id: str, body: CheckinBody):
    """Mark a guest as arrived and record how many people actually showed."""
    b = _get_booking(booking_id)
    if b["status"] != "confirmed":
        raise HTTPException(status_code=400, detail="This booking is not confirmed — cannot check in.")

    already = bool(b.get("checked_in"))
    update = {"checked_in": True, "heads_present": body.heads_present}
    if not already:
        update["checked_in_at"] = datetime.now(timezone.utc).isoformat()

    res = db().table("bookings").update(update).eq("id", booking_id).execute()
    row = res.data[0]
    return {
        "id": row["id"],
        "full_name": row["full_name"],
        "table_id": row.get("table_id"),
        "guests": row["guests"],
        "heads_present": row.get("heads_present", 0),
        "checked_in": row.get("checked_in", False),
        "checked_in_at": row.get("checked_in_at"),
        "already_checked_in": already,
    }

@app.get("/api/reception/tables", dependencies=[Depends(require_reception)])
def reception_tables():
    """Live per-table board: who's reserved, booked pax, and heads seated so far."""
    tables = db().table("tables").select("*").execute().data or []
    confirmed = db().table("bookings").select("*") \
        .eq("status", "confirmed") \
        .not_.is_("table_id", "null") \
        .execute().data or []

    by_table = {}
    for bk in confirmed:
        by_table.setdefault(bk["table_id"], []).append(bk)

    out = []
    for t in tables:
        bks = by_table.get(t["id"], [])
        seated = sum((bk.get("heads_present") or 0) for bk in bks if bk.get("checked_in"))
        booked = sum((bk.get("guests") or 0) for bk in bks)
        out.append({
            "id": t["id"],
            "package": t.get("package"),
            "capacity": _table_capacity(t.get("package")),
            "reserved_by": [bk["full_name"] for bk in bks],
            "booked_pax": booked,
            "seated": seated,
            "any_checked_in": any(bk.get("checked_in") for bk in bks),
        })
    # Sort by table id for a stable board
    out.sort(key=lambda x: str(x["id"]))
    return {"tables": out}
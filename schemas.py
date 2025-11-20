"""
Database Schemas for the Bakery Workforce Management App

Each Pydantic model maps to a MongoDB collection (lowercased class name).
Use these models for validation before inserting/updating documents.

Note: To ensure maximum compatibility across runtimes, we use string fields
for date/time values (ISO strings like YYYY-MM-DD, HH:MM, or ISO datetime).
"""

from pydantic import BaseModel, Field
from typing import Optional

class User(BaseModel):
    """
    Employees and admins
    Collection: "user"
    """
    username: str = Field(..., description="Unique login username")
    full_name: str = Field(..., description="Employee full name")
    role: str = Field(..., description="Position in bakery: baker | cashier | cleaner | admin")
    is_admin: bool = Field(False, description="Has admin privileges")
    password_hash: str = Field(..., description="SHA256 salted password hash")
    active: bool = Field(True, description="Is the user active")

class Session(BaseModel):
    """
    Active login sessions
    Collection: "session"
    """
    user_id: str = Field(..., description="Linked user _id as string")
    token: str = Field(..., description="Session token (UUID4)")
    expires_at: str = Field(..., description="Expiration timestamp ISO (UTC)")

class Shift(BaseModel):
    """
    Work schedule entries
    Collection: "shift"
    """
    user_id: str = Field(..., description="Employee id as string")
    date: str = Field(..., description="Shift date (YYYY-MM-DD)")
    start_time: str = Field(..., description="Shift start time (HH:MM)")
    end_time: str = Field(..., description="Shift end time (HH:MM)")
    note: Optional[str] = Field(None, description="Optional note")

class TimeLog(BaseModel):
    """
    Clock-in/clock-out records
    Collection: "timelog"
    """
    user_id: str = Field(..., description="Employee id as string")
    date: str = Field(..., description="Date of work (YYYY-MM-DD)")
    clock_in: str = Field(..., description="Clock in time ISO (UTC)")
    clock_out: Optional[str] = Field(None, description="Clock out time ISO (UTC)")

class Notification(BaseModel):
    """
    Important messages for employees
    Collection: "notification"
    """
    title: str = Field(..., description="Title")
    message: str = Field(..., description="Detail message")
    level: str = Field("info", description="info | warning | critical")
    audience: str = Field("all", description="all | role:<role> | user:<user_id>")

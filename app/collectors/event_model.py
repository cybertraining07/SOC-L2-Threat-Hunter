
from datetime import datetime, timezone
from typing import Optional, Any
from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    source: str
    event_type: str
    severity: str = "LOW"
    username: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    description: str
    raw_data: dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "forbid"

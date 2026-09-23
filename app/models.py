from datetime import datetime, timezone

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    source: str = Field(..., min_length=1, max_length=255)
    event_type: str = Field(..., min_length=1, max_length=100)
    username: str | None = Field(default=None, max_length=255)
    source_ip: str | None = None
    endpoint: str | None = Field(default=None, max_length=500)
    status_code: int | None = Field(default=None, ge=100, le=599)
    message: str | None = Field(default=None, max_length=2000)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

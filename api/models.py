"""
models.py — SQLAlchemy ORM models for audit session persistence.
"""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class AuditSession(Base):
    """Top-level audit session record."""

    __tablename__ = "audit_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    model_name: Mapped[str] = mapped_column(String(128), default="mock-llm-v1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, server_default=func.now()
    )
    total_attacks: Mapped[int] = mapped_column(Integer, default=0)
    safe_responses: Mapped[int] = mapped_column(Integer, default=0)
    unsafe_responses: Mapped[int] = mapped_column(Integer, default=0)
    overall_safety_score: Mapped[float] = mapped_column(Float, default=0.0)
    refusal_rate: Mapped[float] = mapped_column(Float, default=0.0)
    harmful_content_rate: Mapped[float] = mapped_column(Float, default=0.0)
    leakage_rate: Mapped[float] = mapped_column(Float, default=0.0)
    elapsed_total_ms: Mapped[int] = mapped_column(Integer, default=0)

    # JSON-encoded fields (stored as TEXT)
    safety_dimensions_json: Mapped[str] = mapped_column(Text, default="{}")
    recommendations_json: Mapped[str] = mapped_column(Text, default="[]")
    owasp_compliance_json: Mapped[str] = mapped_column(Text, default="[]")

    @property
    def safety_dimensions(self) -> dict:
        return json.loads(self.safety_dimensions_json)

    @safety_dimensions.setter
    def safety_dimensions(self, value: dict) -> None:
        self.safety_dimensions_json = json.dumps(value)

    @property
    def recommendations(self) -> list:
        return json.loads(self.recommendations_json)

    @recommendations.setter
    def recommendations(self, value: list) -> None:
        self.recommendations_json = json.dumps(value)

    @property
    def owasp_compliance(self) -> list:
        return json.loads(self.owasp_compliance_json)

    @owasp_compliance.setter
    def owasp_compliance(self, value: list) -> None:
        self.owasp_compliance_json = json.dumps(value)


class AttackResult(Base):
    """Individual attack result within a session."""

    __tablename__ = "attack_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)

    # Attack metadata
    attack_id: Mapped[str] = mapped_column(String(16))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    owasp_ref: Mapped[str] = mapped_column(String(64))

    # Response
    response_text: Mapped[str] = mapped_column(Text)
    is_simulated_failure: Mapped[bool] = mapped_column(Boolean, default=False)

    # Detection
    is_safe: Mapped[bool] = mapped_column(Boolean, default=True)
    safety_score: Mapped[float] = mapped_column(Float, default=1.0)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    refusal_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    detection_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    triggered_rules_json: Mapped[str] = mapped_column(Text, default="[]")
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, server_default=func.now()
    )

    @property
    def triggered_rules(self) -> list:
        return json.loads(self.triggered_rules_json)

    @triggered_rules.setter
    def triggered_rules(self, value: list) -> None:
        self.triggered_rules_json = json.dumps(value)

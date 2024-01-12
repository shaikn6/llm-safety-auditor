"""
main.py — FastAPI application for LLM Safety Auditor.

Endpoints:
  POST /audit/run          — run a new audit session
  GET  /audit/{session_id} — retrieve session summary
  GET  /audit/{session_id}/results — retrieve all attack results
  GET  /audit/sessions/list — list all sessions
  GET  /attacks            — list all available attack prompts
  GET  /attacks/{id}       — get a single attack prompt
  POST /detect             — run the detector on arbitrary text
  GET  /health             — healthcheck
"""

from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.database import get_db, init_db
from api.models import AttackResult as DBAttackResult
from api.models import AuditSession as DBAuditSession
from auditor.attack_library import (
    ALL_ATTACKS,
    AttackCategory,
    Severity,
    get_attack_by_id,
    get_attacks_by_category,
    get_category_stats,
)
from auditor.detector import SafetyDetector
from auditor.evaluator import SafetyEvaluator
from auditor.mock_llm import MockLLM

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="LLM Safety Auditor API",
    description=(
        "Automated red-teaming and safety evaluation framework for LLM deployments. "
        "Simulates adversarial attacks and scores model safety across OWASP LLM Top 10."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    init_db()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class AuditRunRequest(BaseModel):
    session_id: Optional[str] = None
    categories: Optional[List[str]] = None   # filter by AttackCategory
    severities: Optional[List[str]] = None   # filter by Severity
    limit: Optional[int] = None
    use_semantic_detector: bool = False       # set True if sentence-transformers installed
    llm_seed: int = 42


class AttackPromptOut(BaseModel):
    id: str
    category: str
    template: str
    expected_behavior: str
    severity: str
    owasp_ref: str
    tags: List[str]


class DetectionRequest(BaseModel):
    text: str
    use_semantic: bool = False


class DetectionOut(BaseModel):
    is_safe: bool
    confidence: float
    triggered_rules: List[str]
    category: Optional[str]
    layers_checked: List[str]
    refusal_detected: bool
    semantic_score: float


class SessionSummaryOut(BaseModel):
    session_id: str
    model_name: str
    total_attacks: int
    safe_responses: int
    unsafe_responses: int
    overall_safety_score: float
    refusal_rate: float
    harmful_content_rate: float
    leakage_rate: float
    elapsed_total_ms: int
    safety_dimensions: dict
    recommendations: list
    owasp_compliance: list


class AttackResultOut(BaseModel):
    attack_id: str
    category: str
    severity: str
    owasp_ref: str
    is_safe: bool
    safety_score: float
    confidence: float
    refusal_detected: bool
    detection_category: Optional[str]
    triggered_rules: list
    elapsed_ms: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _persist_session(db: Session, report) -> DBAuditSession:
    session_row = DBAuditSession(
        session_id=report.session_id,
        model_name=report.model_name,
        total_attacks=report.total_attacks,
        safe_responses=report.safe_responses,
        unsafe_responses=report.unsafe_responses,
        overall_safety_score=report.overall_safety_score,
        refusal_rate=report.refusal_rate,
        harmful_content_rate=report.harmful_content_rate,
        leakage_rate=report.leakage_rate,
        elapsed_total_ms=report.elapsed_total_ms,
    )
    session_row.safety_dimensions = report.safety_dimensions
    session_row.recommendations = report.recommendations
    session_row.owasp_compliance = [
        {
            "owasp_id": o.owasp_id,
            "title": o.title,
            "status": o.status,
            "attack_success_rate": o.attack_success_rate,
            "notes": o.notes,
        }
        for o in report.owasp_compliance
    ]
    db.add(session_row)

    for r in report.attack_results:
        row = DBAttackResult(
            session_id=report.session_id,
            attack_id=r.attack.id,
            category=r.attack.category.value,
            severity=r.attack.severity.value,
            owasp_ref=r.attack.owasp_ref,
            response_text=r.llm_response.response_text,
            is_simulated_failure=r.llm_response.is_simulated_failure,
            is_safe=r.detection.is_safe,
            safety_score=r.safety_score,
            confidence=r.detection.confidence,
            refusal_detected=r.detection.refusal_detected,
            detection_category=r.detection.category,
            elapsed_ms=r.elapsed_ms,
        )
        row.triggered_rules = r.detection.triggered_rules
        db.add(row)

    db.commit()
    db.refresh(session_row)
    return session_row


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "llm-safety-auditor"}


@app.post("/audit/run", response_model=SessionSummaryOut)
def run_audit(req: AuditRunRequest, db: Session = Depends(get_db)):
    """Run a new adversarial audit session against the mock LLM."""
    session_id = req.session_id or f"session-{uuid.uuid4().hex[:8]}"

    # Parse optional filters
    categories = None
    if req.categories:
        try:
            categories = [AttackCategory(c) for c in req.categories]
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    severities = None
    if req.severities:
        try:
            severities = [Severity(s) for s in req.severities]
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    llm = MockLLM(global_seed=req.llm_seed)
    detector = SafetyDetector(use_semantic=req.use_semantic_detector)
    evaluator = SafetyEvaluator(llm=llm, detector=detector, session_id=session_id)

    report = evaluator.run(categories=categories, severities=severities, limit=req.limit)
    _persist_session(db, report)

    return SessionSummaryOut(
        session_id=report.session_id,
        model_name=report.model_name,
        total_attacks=report.total_attacks,
        safe_responses=report.safe_responses,
        unsafe_responses=report.unsafe_responses,
        overall_safety_score=report.overall_safety_score,
        refusal_rate=report.refusal_rate,
        harmful_content_rate=report.harmful_content_rate,
        leakage_rate=report.leakage_rate,
        elapsed_total_ms=report.elapsed_total_ms,
        safety_dimensions=report.safety_dimensions,
        recommendations=report.recommendations,
        owasp_compliance=[
            {
                "owasp_id": o.owasp_id,
                "title": o.title,
                "status": o.status,
                "attack_success_rate": o.attack_success_rate,
            }
            for o in report.owasp_compliance
        ],
    )


@app.get("/audit/sessions/list")
def list_sessions(db: Session = Depends(get_db)):
    """List all audit sessions."""
    sessions = db.query(DBAuditSession).order_by(DBAuditSession.created_at.desc()).all()
    return [
        {
            "session_id": s.session_id,
            "model_name": s.model_name,
            "created_at": s.created_at.isoformat(),
            "overall_safety_score": s.overall_safety_score,
            "total_attacks": s.total_attacks,
            "unsafe_responses": s.unsafe_responses,
        }
        for s in sessions
    ]


@app.get("/audit/{session_id}", response_model=SessionSummaryOut)
def get_session(session_id: str, db: Session = Depends(get_db)):
    """Retrieve audit session summary by ID."""
    session = db.query(DBAuditSession).filter(
        DBAuditSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

    return SessionSummaryOut(
        session_id=session.session_id,
        model_name=session.model_name,
        total_attacks=session.total_attacks,
        safe_responses=session.safe_responses,
        unsafe_responses=session.unsafe_responses,
        overall_safety_score=session.overall_safety_score,
        refusal_rate=session.refusal_rate,
        harmful_content_rate=session.harmful_content_rate,
        leakage_rate=session.leakage_rate,
        elapsed_total_ms=session.elapsed_total_ms,
        safety_dimensions=session.safety_dimensions,
        recommendations=session.recommendations,
        owasp_compliance=session.owasp_compliance,
    )


@app.get("/audit/{session_id}/results", response_model=List[AttackResultOut])
def get_session_results(
    session_id: str,
    category: Optional[str] = Query(None),
    unsafe_only: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Retrieve all attack results for a session."""
    q = db.query(DBAttackResult).filter(DBAttackResult.session_id == session_id)
    if category:
        q = q.filter(DBAttackResult.category == category)
    if unsafe_only:
        q = q.filter(DBAttackResult.is_safe == False)  # noqa: E712

    rows = q.all()
    return [
        AttackResultOut(
            attack_id=r.attack_id,
            category=r.category,
            severity=r.severity,
            owasp_ref=r.owasp_ref,
            is_safe=r.is_safe,
            safety_score=r.safety_score,
            confidence=r.confidence,
            refusal_detected=r.refusal_detected,
            detection_category=r.detection_category,
            triggered_rules=r.triggered_rules,
            elapsed_ms=r.elapsed_ms,
        )
        for r in rows
    ]


@app.get("/attacks", response_model=List[AttackPromptOut])
def list_attacks(
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List all available attack prompts with optional filters."""
    attacks = ALL_ATTACKS[:]

    if category:
        try:
            cat = AttackCategory(category)
            attacks = [a for a in attacks if a.category == cat]
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid category: {category}")

    if severity:
        try:
            sev = Severity(severity)
            attacks = [a for a in attacks if a.severity == sev]
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid severity: {severity}")

    return [
        AttackPromptOut(
            id=a.id,
            category=a.category.value,
            template=a.template,
            expected_behavior=a.expected_behavior,
            severity=a.severity.value,
            owasp_ref=a.owasp_ref,
            tags=a.tags,
        )
        for a in attacks
    ]


@app.get("/attacks/{attack_id}", response_model=AttackPromptOut)
def get_attack(attack_id: str):
    """Get a single attack prompt by ID."""
    attack = get_attack_by_id(attack_id)
    if not attack:
        raise HTTPException(status_code=404, detail=f"Attack '{attack_id}' not found")
    return AttackPromptOut(
        id=attack.id,
        category=attack.category.value,
        template=attack.template,
        expected_behavior=attack.expected_behavior,
        severity=attack.severity.value,
        owasp_ref=attack.owasp_ref,
        tags=attack.tags,
    )


@app.post("/detect", response_model=DetectionOut)
def detect(req: DetectionRequest):
    """Run the safety detector on arbitrary text."""
    detector = SafetyDetector(use_semantic=req.use_semantic)
    result = detector.analyze(req.text)
    return DetectionOut(
        is_safe=result.is_safe,
        confidence=result.confidence,
        triggered_rules=result.triggered_rules,
        category=result.category,
        layers_checked=result.layers_checked,
        refusal_detected=result.refusal_detected,
        semantic_score=result.semantic_score,
    )


@app.get("/attacks/stats/categories")
def attack_category_stats():
    """Return attack count per category."""
    return get_category_stats()

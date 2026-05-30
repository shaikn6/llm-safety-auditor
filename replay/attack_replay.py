"""
replay/attack_replay.py — Attack replay suite with SQLite persistence (V2).

Features:
  - Store every attack + response + outcome in SQLite
  - Regression testing: re-run all past attacks on a new model version, flag regressions
  - diff_report(model_v1, model_v2): which attacks now succeed/fail vs before
  - Timeline: safety score over time as model is updated
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional

from auditor.attack_library import AttackCategory, AttackPrompt, Severity
from auditor.detector import DetectionResult, SafetyDetector
from auditor.evaluator import AttackResult, AuditReport, SafetyEvaluator
from auditor.mock_llm import LLMResponse, MockLLM


# ---------------------------------------------------------------------------
# Default database path
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "replay_store.db"


# ---------------------------------------------------------------------------
# SQLite schema helpers
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS attack_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         TEXT    NOT NULL,
    model_version  TEXT    NOT NULL,
    attack_id      TEXT    NOT NULL,
    category       TEXT    NOT NULL,
    severity       TEXT    NOT NULL,
    template       TEXT    NOT NULL,
    response_text  TEXT    NOT NULL,
    is_safe        INTEGER NOT NULL,
    confidence     REAL    NOT NULL,
    refusal        INTEGER NOT NULL,
    triggered_json TEXT    NOT NULL,   -- JSON array of triggered rule strings
    safety_score   REAL    NOT NULL,
    elapsed_ms     INTEGER NOT NULL,
    created_at     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_run_id ON attack_runs(run_id);
CREATE INDEX IF NOT EXISTS idx_model ON attack_runs(model_version);
CREATE INDEX IF NOT EXISTS idx_attack ON attack_runs(attack_id);

CREATE TABLE IF NOT EXISTS audit_runs (
    run_id          TEXT PRIMARY KEY,
    model_version   TEXT NOT NULL,
    total_attacks   INTEGER NOT NULL,
    safety_score    REAL NOT NULL,
    unsafe_count    INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    notes           TEXT
);
"""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class StoredAttackRun:
    run_id: str
    model_version: str
    attack_id: str
    category: str
    severity: str
    template: str
    response_text: str
    is_safe: bool
    confidence: float
    refusal: bool
    triggered_rules: List[str]
    safety_score: float
    elapsed_ms: int
    created_at: str


@dataclass
class RegressionFinding:
    attack_id: str
    category: str
    severity: str
    template: str
    v1_safe: bool
    v2_safe: bool
    regression_type: str           # "NEW_FAILURE" | "NEW_PASS"
    v1_model: str
    v2_model: str

    @property
    def is_regression(self) -> bool:
        """True = was safe in V1, now unsafe in V2 (bad)."""
        return self.regression_type == "NEW_FAILURE"

    @property
    def is_improvement(self) -> bool:
        """True = was unsafe in V1, now safe in V2 (good)."""
        return self.regression_type == "NEW_PASS"


@dataclass
class DiffReport:
    model_v1: str
    model_v2: str
    regressions: List[RegressionFinding]     # safe → unsafe (bad)
    improvements: List[RegressionFinding]    # unsafe → safe (good)
    unchanged_safe: int
    unchanged_unsafe: int
    v1_safety_score: Optional[float] = None
    v2_safety_score: Optional[float] = None

    @property
    def net_change(self) -> int:
        """Positive = more regressions than improvements (worse)."""
        return len(self.regressions) - len(self.improvements)

    def summary(self) -> str:
        lines = [
            f"Diff Report: {self.model_v1} → {self.model_v2}",
            f"  Regressions (new failures): {len(self.regressions)}",
            f"  Improvements (new passes):  {len(self.improvements)}",
            f"  Unchanged safe:             {self.unchanged_safe}",
            f"  Unchanged unsafe:           {self.unchanged_unsafe}",
            f"  Net change:                 {self.net_change:+d}",
        ]
        if self.v1_safety_score is not None and self.v2_safety_score is not None:
            delta = self.v2_safety_score - self.v1_safety_score
            lines.append(
                f"  Safety score: {self.v1_safety_score:.1f} → {self.v2_safety_score:.1f} ({delta:+.1f})"
            )
        return "\n".join(lines)


@dataclass
class TimelinePoint:
    run_id: str
    model_version: str
    safety_score: float
    total_attacks: int
    unsafe_count: int
    created_at: str


# ---------------------------------------------------------------------------
# Replay store
# ---------------------------------------------------------------------------

class ReplayStore:
    """
    SQLite-backed store for attack runs.

    Usage:
        store = ReplayStore()
        store.save_run("run-001", "gpt-4o", report)
        regressions = store.diff_report("gpt-4o-v1", "gpt-4o-v2")
    """

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "ReplayStore":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _init_schema(self) -> None:
        self._conn.executescript(_DDL)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Persist
    # ------------------------------------------------------------------

    def save_run(
        self,
        run_id: str,
        model_version: str,
        report: AuditReport,
        notes: str = "",
    ) -> None:
        """Persist all attack results from an AuditReport."""
        created_at = datetime.now(timezone.utc).isoformat()

        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO audit_runs
                    (run_id, model_version, total_attacks, safety_score, unsafe_count, created_at, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    model_version,
                    report.total_attacks,
                    report.overall_safety_score,
                    report.unsafe_responses,
                    created_at,
                    notes,
                ),
            )

            rows = [
                (
                    run_id,
                    model_version,
                    ar.attack.id,
                    ar.attack.category.value,
                    ar.attack.severity.value,
                    ar.attack.template,
                    ar.llm_response.response_text,
                    int(not ar.is_successful_attack),
                    ar.detection.confidence,
                    int(ar.detection.refusal_detected),
                    json.dumps(ar.detection.triggered_rules),
                    ar.safety_score,
                    ar.elapsed_ms,
                    created_at,
                )
                for ar in report.attack_results
            ]
            self._conn.executemany(
                """
                INSERT INTO attack_runs
                    (run_id, model_version, attack_id, category, severity, template,
                     response_text, is_safe, confidence, refusal, triggered_json,
                     safety_score, elapsed_ms, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_runs_for_model(self, model_version: str) -> List[StoredAttackRun]:
        rows = self._conn.execute(
            "SELECT * FROM attack_runs WHERE model_version = ? ORDER BY created_at",
            (model_version,),
        ).fetchall()
        return [self._row_to_stored(r) for r in rows]

    def get_latest_run_id(self, model_version: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT run_id FROM audit_runs WHERE model_version = ? ORDER BY created_at DESC LIMIT 1",
            (model_version,),
        ).fetchone()
        return row["run_id"] if row else None

    def list_audit_runs(self) -> List[dict]:
        rows = self._conn.execute(
            "SELECT * FROM audit_runs ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_attack_history(self, attack_id: str) -> List[StoredAttackRun]:
        rows = self._conn.execute(
            "SELECT * FROM attack_runs WHERE attack_id = ? ORDER BY created_at",
            (attack_id,),
        ).fetchall()
        return [self._row_to_stored(r) for r in rows]

    def _row_to_stored(self, row: sqlite3.Row) -> StoredAttackRun:
        return StoredAttackRun(
            run_id=row["run_id"],
            model_version=row["model_version"],
            attack_id=row["attack_id"],
            category=row["category"],
            severity=row["severity"],
            template=row["template"],
            response_text=row["response_text"],
            is_safe=bool(row["is_safe"]),
            confidence=row["confidence"],
            refusal=bool(row["refusal"]),
            triggered_rules=json.loads(row["triggered_json"]),
            safety_score=row["safety_score"],
            elapsed_ms=row["elapsed_ms"],
            created_at=row["created_at"],
        )

    # ------------------------------------------------------------------
    # Regression testing
    # ------------------------------------------------------------------

    def diff_report(self, model_v1: str, model_v2: str) -> DiffReport:
        """
        Compare outcomes for every attack that exists in both model versions.

        Returns a DiffReport listing regressions (was safe → now unsafe)
        and improvements (was unsafe → now safe).
        """
        v1_runs = {r.attack_id: r for r in self.get_runs_for_model(model_v1)}
        v2_runs = {r.attack_id: r for r in self.get_runs_for_model(model_v2)}

        common_ids = set(v1_runs.keys()) & set(v2_runs.keys())

        regressions: List[RegressionFinding] = []
        improvements: List[RegressionFinding] = []
        unchanged_safe = 0
        unchanged_unsafe = 0

        for attack_id in sorted(common_ids):
            r1 = v1_runs[attack_id]
            r2 = v2_runs[attack_id]

            if r1.is_safe and not r2.is_safe:
                regressions.append(
                    RegressionFinding(
                        attack_id=attack_id,
                        category=r1.category,
                        severity=r1.severity,
                        template=r1.template,
                        v1_safe=True,
                        v2_safe=False,
                        regression_type="NEW_FAILURE",
                        v1_model=model_v1,
                        v2_model=model_v2,
                    )
                )
            elif not r1.is_safe and r2.is_safe:
                improvements.append(
                    RegressionFinding(
                        attack_id=attack_id,
                        category=r1.category,
                        severity=r1.severity,
                        template=r1.template,
                        v1_safe=False,
                        v2_safe=True,
                        regression_type="NEW_PASS",
                        v1_model=model_v1,
                        v2_model=model_v2,
                    )
                )
            elif r1.is_safe and r2.is_safe:
                unchanged_safe += 1
            else:
                unchanged_unsafe += 1

        # Retrieve stored safety scores
        v1_score = self._get_safety_score(model_v1)
        v2_score = self._get_safety_score(model_v2)

        return DiffReport(
            model_v1=model_v1,
            model_v2=model_v2,
            regressions=regressions,
            improvements=improvements,
            unchanged_safe=unchanged_safe,
            unchanged_unsafe=unchanged_unsafe,
            v1_safety_score=v1_score,
            v2_safety_score=v2_score,
        )

    def _get_safety_score(self, model_version: str) -> Optional[float]:
        row = self._conn.execute(
            "SELECT safety_score FROM audit_runs WHERE model_version = ? ORDER BY created_at DESC LIMIT 1",
            (model_version,),
        ).fetchone()
        return row["safety_score"] if row else None

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def safety_timeline(self) -> List[TimelinePoint]:
        """
        Return the safety score for each audit run, ordered by time.

        Use for a line chart of safety score over model versions.
        """
        rows = self._conn.execute(
            "SELECT * FROM audit_runs ORDER BY created_at ASC"
        ).fetchall()
        return [
            TimelinePoint(
                run_id=r["run_id"],
                model_version=r["model_version"],
                safety_score=r["safety_score"],
                total_attacks=r["total_attacks"],
                unsafe_count=r["unsafe_count"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Regression runner
    # ------------------------------------------------------------------

    def run_regression(
        self,
        model_version: str,
        llm: Optional[MockLLM] = None,
        detector: Optional[SafetyDetector] = None,
        run_id: Optional[str] = None,
        notes: str = "",
    ) -> AuditReport:
        """
        Re-run all past attacks on a new model version and store the results.

        Parameters
        ----------
        model_version : label for the new model being tested
        llm           : LLM instance to use (default: MockLLM with seed 42)
        detector      : SafetyDetector instance (default: no semantic)
        run_id        : explicit run ID (default: timestamp)
        notes         : freeform annotation stored with the run
        """
        rid = run_id or f"regression-{model_version}-{int(time.time())}"
        _llm = llm or MockLLM(global_seed=42)
        _det = detector or SafetyDetector(use_semantic=False)
        ev = SafetyEvaluator(llm=_llm, detector=_det, session_id=rid)
        report = ev.run()
        self.save_run(rid, model_version, report, notes=notes)
        return report

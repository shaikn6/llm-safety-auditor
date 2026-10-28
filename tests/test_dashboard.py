"""The Streamlit dashboard must render without raising.

A syntax-level or import-level break in dashboard/app.py is invisible to the rest of
the suite because nothing else imports it, and `streamlit run` only shows the error
in the browser.
"""

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"


def test_dashboard_renders_without_exception():
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    assert not at.exception, [e.value for e in at.exception]
    assert {b.label for b in at.button} >= {
        "▶ Run Red-Team Audit",
        "🔍 Analyze Response",
    }

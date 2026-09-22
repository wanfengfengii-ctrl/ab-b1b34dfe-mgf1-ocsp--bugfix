"""Pytest wrapper for the code-level RSASSA-PSS parameter regression.

The scenarios live in ``acceptance.pss_regression`` so the exact same checks
run (a) via pytest, (b) inside the ``api-a`` container as
``python -m acceptance.pss_regression`` and (c) as the final phase of the
``verify`` acceptance service.  Every failed scenario fails this module with
a non-zero exit code.
"""
from __future__ import annotations

import pytest

from acceptance.pss_regression import run_all


@pytest.mark.parametrize("finding", run_all(), ids=lambda f: f.name)
def test_pss_parameter_regression(finding):
    assert finding.ok, finding.detail

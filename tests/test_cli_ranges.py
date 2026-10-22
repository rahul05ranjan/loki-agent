"""Range validation for `loki run` numeric options (#23).

`--duration` and `--fault-rate` previously accepted nonsense values and
only failed later (or silently misbehaved): a zero/negative duration and a
fault-rate outside 0.0..1.0 got through the parser. Typer's built-in range
validation now rejects them at parse time with exit code 2, before any
browser starts.
"""

import re

from typer.testing import CliRunner

from loki.cli import app


def _clean(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)


def _invoke(args):
    return CliRunner(env={"NO_COLOR": "1", "TERM": "dumb"}).invoke(app, args)


def test_zero_duration_is_rejected_at_parse_time():
    result = _invoke(["run", "--duration", "0", "http://localhost:8000"])
    assert result.exit_code == 2
    assert "duration" in _clean(result.output).lower()


def test_negative_duration_is_rejected_at_parse_time():
    result = _invoke(["run", "--duration", "-5", "http://localhost:8000"])
    assert result.exit_code == 2


def test_fault_rate_above_one_is_rejected_at_parse_time():
    result = _invoke(["run", "--fault-rate", "1.5", "http://localhost:8000"])
    assert result.exit_code == 2
    assert "fault" in _clean(result.output).lower()


def test_negative_fault_rate_is_rejected_at_parse_time():
    result = _invoke(["run", "--fault-rate", "-3", "http://localhost:8000"])
    assert result.exit_code == 2


def test_run_help_still_parses():
    """The option signatures (including the new ranges) still construct."""
    result = _invoke(["run", "--help"])
    assert result.exit_code == 0
    assert "--duration" in _clean(result.output)
    assert "--fault-rate" in _clean(result.output)

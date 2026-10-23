from importlib.resources import files
from pathlib import Path
import pytest
from loki.engine.html_reporter import HTMLReporter
from loki.engine.reporter import IncidentReporter
from loki.models import IncidentReport
from loki.templates import render

TEMPLATE_NAMES = ("repro_test.py.tmpl", "concurrent_repro_test.py.tmpl", "report.html")


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
def test_templates_ship_inside_the_package(name):
    assert files("loki.templates").joinpath(name).is_file()


def test_render_refuses_missing_values():
    with pytest.raises(KeyError):
        render("report.html", run_id="only-one-value")


@pytest.mark.parametrize("report", [
    IncidentReport(target_url="http://localhost:8000", crashes=["x"]),
    IncidentReport(
        target_url="http://localhost:8000/it's",
        persona_name="Swarm",
        seed=42,
        device_name="iPhone 15",
        orientation="landscape",
        browser_name="opera",
        replay_trace=[{"kind": "fill", "selector": "#q", "value": "a'\"b\\c"}],
        api_faults=[{"url": "http://localhost:8000/api", "status": 500, "body": {"error": "x"}}],
    ),
    IncidentReport(target_url="http://localhost:8000", concurrency=3, concurrency_lanes=[{"lane": 0, "selector": "#pay"}]),
    IncidentReport(target_url="http://localhost:8000", concurrency=2),
], ids=["minimal", "device-and-tricky-values", "concurrent", "concurrent-no-selector"])
def test_generated_repro_scripts_are_valid_python(report):
    script = IncidentReporter()._generate_repro_script(report)
    compile(script, "repro_test.py", "exec")
    assert "$" not in script.split('"""', 2)[2].replace("${", "")  # no unrendered placeholders


HOSTILE_URLS = [
    'http://localhost:8000/?q="a\\b',
    'http://localhost:8000/?q=\\x',
    'http://localhost:8000/?q=\\u12',
    'http://localhost:8000/?q="',
]


@pytest.mark.parametrize("hostile_url", HOSTILE_URLS)
def test_hostile_target_url_yields_compilable_scripts(hostile_url: str) -> None:
    """A URL with quotes or backslashes must survive template embedding (#25)."""
    single = IncidentReport(target_url=hostile_url, crashes=["x"])
    concurrent = IncidentReport(target_url=hostile_url, concurrency=2)

    script = IncidentReporter()._generate_repro_script(single)
    compile(script, "repro_test.py", "exec")
    assert f"TARGET_URL = {hostile_url!r}" in script
    # The docstring must also stay compilable: no raw backslash or quote escapes.
    assert f"Target: {hostile_url!r}" in script

    script = IncidentReporter()._generate_concurrent_repro_script(concurrent)
    compile(script, "concurrent_repro_test.py", "exec")
    assert f"TARGET_URL = {hostile_url!r}" in script
    assert f"Target: {hostile_url!r}" in script


def test_generated_scripts_navigate_to_the_original_url():
    """The embedded literal must be exactly the reported URL, not a mangled one."""
    script = IncidentReporter()._generate_repro_script(
        IncidentReport(target_url=HOSTILE_URLS[0], crashes=["x"])
    )
    assert "page.goto(TARGET_URL, wait_until=" in script
    # No raw, un-embedded copy of the URL is left in the script body.
    assert 'goto("http' not in script


def test_repro_device_is_resolved_at_runtime():
    report = IncidentReport(target_url="http://localhost:8000", crashes=["x"], device_name="Pixel 7")
    script = IncidentReporter()._generate_repro_script(report)
    assert "DEVICE_NAME = 'Pixel 7'" in script
    assert "browser = p.chromium.launch(headless=False)" in script


def test_html_report_escapes_values(tmp_path: Path):
    out = HTMLReporter.generate({"run_id": "<script>alert(1)</script>", "target_url": "http://x/?a=<b>"}, tmp_path / "r.html")
    content = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content
    assert "$" not in content

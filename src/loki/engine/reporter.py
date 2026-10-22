import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any
from loki.models import IncidentReport
from loki.engine.browser import normalize_browser_name
from loki.engine.html_reporter import HTMLReporter
from loki.engine.scrubber import NetworkScrubber
from loki.templates import render


class IncidentReporter:
    """Persists crash evidence and synthesizes automated reproduction scripts and HTML reports."""

    def __init__(self, base_output_dir: str = ".loki/runs"):
        self.base_output_dir = Path(base_output_dir)

    def save_session(
        self,
        report: IncidentReport,
        rules_evaluations: list[dict[str, Any]] | None = None,
    ) -> Path:
        """Saves a complete test execution session bundle with HTML report and video."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = self.base_output_dir / f"run_{timestamp}"
        run_dir.mkdir(parents=True, exist_ok=True)

        # 1. Relocate recorded video to the incident directory
        final_video_file = None
        if report.video_path and Path(report.video_path).exists():
            dest_video = run_dir / "replay.webm"
            shutil.move(report.video_path, dest_video)
            final_video_file = "replay.webm"

        # 2. Relocate and scrub recorded network trace (HAR)
        final_har_file = None
        if report.har_path and Path(report.har_path).exists():
            dest_har = run_dir / "network.har"
            scrubbed = NetworkScrubber.scrub_har_file(Path(report.har_path), dest_har)
            if scrubbed and dest_har.exists():
                final_har_file = "network.har"
            try:
                Path(report.har_path).unlink(missing_ok=True)
            except Exception:
                pass

        # 3. Save incident metadata in incident.json
        metadata = {
            "run_id": run_dir.name,
            "timestamp": datetime.now().isoformat(),
            "target_url": report.target_url,
            "persona": report.persona_name,
            "browser": report.browser_name,
            "seed": report.seed,
            "device": report.device_name,
            "orientation": report.orientation,
            "duration_seconds": report.duration_seconds,
            "unique_crashes_count": len(set(report.crashes)),
            "crashes": list(set(report.crashes)),
            "console_errors_count": len(report.console_errors),
            "console_errors": report.console_errors,
            "http_errors": report.http_errors,
            "failed_requests": report.failed_requests,
            "unhandled_rejections": report.unhandled_rejections,
            "navigation_errors": report.navigation_errors,
            "resource_failures": report.resource_failures,
            "unexpected_dialogs": report.unexpected_dialogs,
            "layout_issues": report.layout_issues,
            "total_failures_count": report.total_failures_count,
            "actions_executed_count": len(report.actions_taken),
            "actions_taken": report.actions_taken,
            "replay_trace": report.replay_trace,
            "api_faults": report.api_faults,
            "concurrency": report.concurrency,
            "concurrency_lanes": report.concurrency_lanes,
            "rules_evaluations": rules_evaluations or [],
            "video_file": final_video_file,
            "har_file": final_har_file,
        }

        with open(run_dir / "incident.json", "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        # 3. Generate the standalone Playwright reproduction test if crashes occurred,
        # or if this was a concurrency probe (its evidence — e.g. two lanes both
        # succeeding — is not always an exception or HTTP 5xx, so has_crashes alone
        # would miss it; the repro script is the probe's real deliverable)
        if report.has_crashes or report.concurrency > 1:
            repro_code = self._generate_repro_script(report)
            with open(run_dir / "repro_test.py", "w", encoding="utf-8") as f:
                f.write(repro_code)

        # 4. Generate the standalone HTML report
        html_file = run_dir / "report.html"
        HTMLReporter.generate(metadata, html_file)

        return run_dir

    def save_incident(
        self,
        report: IncidentReport,
        rules_evaluations: list[dict[str, Any]] | None = None,
    ) -> Path | None:
        """Creates an incident bundle if crashes or HTTP errors were detected."""
        if not report.has_crashes:
            return None
        return self.save_session(report, rules_evaluations)

    def _generate_repro_script(self, report: IncidentReport) -> str:
        """Synthesizes a minimal standalone Python script reproducing the crash."""
        if report.concurrency > 1:
            return self._generate_concurrent_repro_script(report)

        browser_engine = normalize_browser_name(report.browser_name)
        # repr() produces valid Python literals (proper quoting/escaping) embedded directly
        # as source, so the standalone script needs no extra parsing step.
        return render(
            "repro_test.py.tmpl",
            target_url=report.target_url,
            target_url_literal=repr(report.target_url),
            persona=report.persona_name,
            browser=browser_engine,
            browser_label=browser_engine.capitalize(),
            device_label=report.device_name or "Desktop",
            device_name=repr(report.device_name),
            orientation=report.orientation,
            seed=repr(report.seed),
            replay_trace=repr(report.replay_trace),
            api_faults=repr(report.api_faults),
        )

    def _generate_concurrent_repro_script(self, report: IncidentReport) -> str:
        """Synthesizes a standalone script that reopens `concurrency` independent
        browsers and fires the same synchronized click, mirroring ChaosSandbox's
        concurrency probe so the race condition can be reproduced deterministically."""
        selector = next((lane["selector"] for lane in report.concurrency_lanes if lane.get("selector")), None)
        browser_engine = normalize_browser_name(report.browser_name)
        return render(
            "concurrent_repro_test.py.tmpl",
            target_url=report.target_url,
            target_url_literal=repr(report.target_url),
            concurrency=report.concurrency,
            browser=browser_engine,
            browser_label=browser_engine.capitalize(),
            device_label=report.device_name or "Desktop",
            device_name=repr(report.device_name),
            orientation=report.orientation,
            seed=report.seed,
            selector=repr(selector),
        )

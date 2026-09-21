"""
DDoS detector benchmark instrumentation for PS-26145.

Provides measurement mechanisms for:
  - Flows processed/sec
  - Windows processed/sec
  - Detection latency per window
  - CPU time
  - Peak memory usage

Does NOT fabricate numbers — only provides the measurement tools.
Actual benchmark numbers are generated during validation runs.
"""

from __future__ import annotations

import json
import time
import tracemalloc
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from detectors.ddos.config import DDoSConfig
from detectors.ddos.detector import DDoSDetector
from features.flow_stats import FlowWindow, build_flow_windows
from ingest.parser import ConnRecord, parse_conn_log


@dataclass
class BenchmarkResult:
    """Raw benchmark measurements from a single detector run."""

    # Input
    input_file: str
    total_records: int
    total_windows: int
    alerts_generated: int

    # Timing
    parse_seconds: float
    window_build_seconds: float
    detection_seconds: float
    total_seconds: float

    # Throughput (derived)
    flows_per_second: float
    windows_per_second: float

    # Resource usage
    cpu_time_seconds: float
    peak_memory_bytes: int
    peak_memory_mb: float

    # Config snapshot
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return asdict(self)


def run_benchmark(
    input_path: str | Path,
    config: DDoSConfig | None = None,
) -> BenchmarkResult:
    """
    Run the DDoS detector against an input file and measure performance.

    Args:
        input_path: Path to Zeek conn.log.
        config: Optional DDoS detector configuration.

    Returns:
        :class:`BenchmarkResult` with raw timing and resource measurements.
    """
    config = config or DDoSConfig()
    input_path = Path(input_path)

    # Start memory tracking
    tracemalloc.start()
    cpu_start = time.process_time()
    wall_start = time.perf_counter()

    # Phase 1: Parse
    t0 = time.perf_counter()
    records = list(parse_conn_log(input_path))
    parse_time = time.perf_counter() - t0

    # Phase 2: Window construction
    t0 = time.perf_counter()
    windows = build_flow_windows(records, window_seconds=config.window_seconds)
    window_time = time.perf_counter() - t0

    # Phase 3: Detection
    t0 = time.perf_counter()
    detector = DDoSDetector(config=config)
    alerts = detector.process_windows(windows)
    detect_time = time.perf_counter() - t0

    # Measurements
    wall_total = time.perf_counter() - wall_start
    cpu_total = time.process_time() - cpu_start
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    n_records = len(records)
    n_windows = len(windows)

    return BenchmarkResult(
        input_file=str(input_path),
        total_records=n_records,
        total_windows=n_windows,
        alerts_generated=len(alerts),
        parse_seconds=round(parse_time, 6),
        window_build_seconds=round(window_time, 6),
        detection_seconds=round(detect_time, 6),
        total_seconds=round(wall_total, 6),
        flows_per_second=round(n_records / wall_total, 2) if wall_total > 0 else 0.0,
        windows_per_second=round(n_windows / detect_time, 2) if detect_time > 0 else 0.0,
        cpu_time_seconds=round(cpu_total, 6),
        peak_memory_bytes=peak_mem,
        peak_memory_mb=round(peak_mem / (1024 * 1024), 3),
        config={
            "window_seconds": config.window_seconds,
            "baseline_windows": config.baseline_windows,
            "z_threshold": config.z_threshold,
            "entropy_z_threshold": config.entropy_z_threshold,
        },
    )


def main() -> None:
    """CLI entry point for benchmarking."""
    import argparse
    import logging

    logging.basicConfig(level=logging.WARNING)

    parser = argparse.ArgumentParser(
        description="PS-26145 DDoS Detector Benchmark"
    )
    parser.add_argument(
        "--input", required=True, help="Path to Zeek conn.log"
    )
    parser.add_argument(
        "--output", default="artifacts/ddos/metrics.json",
        help="Output path for benchmark results"
    )
    args = parser.parse_args()

    result = run_benchmark(args.input)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        json.dump(result.to_dict(), f, indent=2)

    print(f"Benchmark complete:")
    print(f"  Records:     {result.total_records}")
    print(f"  Windows:     {result.total_windows}")
    print(f"  Alerts:      {result.alerts_generated}")
    print(f"  Total time:  {result.total_seconds:.4f}s")
    print(f"  Flows/sec:   {result.flows_per_second:.2f}")
    print(f"  Windows/sec: {result.windows_per_second:.2f}")
    print(f"  CPU time:    {result.cpu_time_seconds:.4f}s")
    print(f"  Peak memory: {result.peak_memory_mb:.3f} MB")
    print(f"  Results:     {out_path}")


if __name__ == "__main__":
    main()

import csv
import math
import os
from pathlib import Path

import pytest

from ava.hay_simulation import run_hay_simulation


MODEL_DIR = os.environ.get("AVA_HAY_MODEL_DIR")


@pytest.mark.skipif(
    not MODEL_DIR,
    reason="set AVA_HAY_MODEL_DIR to an extracted ModelDB 139653 archive",
)
def test_hay_simulation_writes_soma_and_apical_traces(tmp_path: Path) -> None:
    traces = []
    for amplitude in (0.0, 0.793):
        output = run_hay_simulation(MODEL_DIR, tmp_path / f"{amplitude}.csv", pulse_amp_nA=amplitude)
        with output.open(newline="", encoding="utf-8") as stream:
            reader = csv.reader(stream)
            assert next(reader) == ["time_ms", "soma_mV", "apical_mV"]
            trace = [tuple(map(float, row)) for row in reader]
        assert len(trace) == 4001
        assert all(math.isfinite(value) for row in trace for value in row)
        assert all(a[0] < b[0] for a, b in zip(trace, trace[1:]))
        traces.append(trace)

    control, pulse = traces
    assert [row[0] for row in pulse] == [row[0] for row in control]
    for channel in (1, 2):
        assert max(p[channel] - c[channel] for p, c in zip(pulse, control)
                   if 20 < p[0] < 60) > 0.1

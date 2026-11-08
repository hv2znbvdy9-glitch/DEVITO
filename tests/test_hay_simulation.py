import csv
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
    pytest.importorskip("neuron")
    output = run_hay_simulation(
        MODEL_DIR,
        tmp_path / "hay.csv",
        duration_ms=2.0,
        pulse_start_ms=0.5,
        pulse_duration_ms=1.0,
        pulse_amp_nA=0.1,
    )

    with output.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert rows
    assert {"time_ms", "soma_mV", "apical_mV"} == set(rows[0])
    assert len(rows) > 10
